# Apache-Content-Security-Policy-Script-Nonce

CSP script nonce module for Apache HTTP server to prevent cross-site scripting attacks.

## Usage
To compile and install the module, use:

[$AP is the installation directory of Apache]
1. $AP/bin/apxs -c mod_csp.c

2. sudo $AP/bin/apxs -i mod_csp.la


To use the module, configure the module in $AP/conf/httpd.conf. See the example in conf directory.




## Method

Based on the Apache Module, our filter chain consists of two parts: CSP Module and Line Editor Module. 
 In CSP Module, we added two type of modifications into the Apache filter, one is Head modification and another is Content modification. In the header, we add the random nonce for the browser. In the Content, we search for the nonce attribute in script tags and replace the nonce with the same random nonce.

In order to achieve the above goal, we call two functions, one is for “random value” generation and one is for implementing “keys” detection and “values substitution”. In the first function (Getting_Nonce ()), we generate a string value as the nonce for the following use. It consists of 27 characters, selected among A~Z, a~z and 0~9. In order to generate a random value, here we use random digits as seeds to choose the character. Getting the nonce value we need, the next step is to detect “keys” and substitute it with the nonce value that just generated. Here, CSP Module calls a function, Replace_Nonce(). This function consists of 2 parts, keys detection and keys substitution. For the reason that keys and nonce values are stored in <script>tags, in keys detection part, keys are detected by regular expression which just match <script> tag.  Getting all the portions, using the addresses that regular expression functions return, with pointer, we can finish substituting all the keys with the random values.

Before processing, the script is like this:
<script script-nonce="$key">   
   /* Valid script here */ 
</scipt>                              
<script>                            
   /* evil injected script here */ 
</script>. 
And after processing, the script will be:

script script-nonce=EkdhEBFlJGLJDEK4TG8NVsda1Yl>   
   /* Valid script here */ 
</scipt>                              
<script>                            
   /* evil injected script here */ 
</script>.

The second Module is line editor. With it, we can successfully handle any scripts sent into the buffer. During our experiments, we find that the file passed to CSP module is cut into several chunks. For example, the file may be cut into chunks shown in Fig 3.1.

<html xmlns = “http://”>< script
 type=””  nonce = “ylai”></script>
</html>
(Fig 3.1)

When this happens, the first chunk will be passed to CSP module and then the second and then the third. Because the regular expression stably matches <script> tags, it would return nothing for there is no integrate <script> tag in a single layer. In order to deal with this problem, we use Line Editor Module, which buffers these chunks and organizes chunks in the unit of lines, to send function Getting_Nonce() a reliable string. 
