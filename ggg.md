# **SQL注入**

原理：SQL注入是一种将SQL语句插入或添加到用户输入参数中,之后再将这些参数传递给后台的SQL服务器加以解析并执行

  成因：1.对用户输入的内容没有进行严格的过滤，直接被带到数据库中执行

  2.程序编写时使用字符串直接拼接sql语句

类型：1.整型    2.字符型

注入方式

联合查询 union select

基于报错得 group by updatexml extractvalue

基于bool 得and

Dnslog外带 load_file('\\\\',(select database()),'xxxx,xxxx,xxxx')

基于时间的

除了使用sleep之外，还有那些方法可以用来进行延时注入？

  heavy query

是否使用addslashes 可以杜绝sql注入？

  1.整型注入

  2.宽字节注入

  3.二次注入

  4.二次编码注入

注入的位置划分？

  1.url请求中

  2.post

  3.cookie

  4.client-ip x-forwarded-for

  5.user-agent

  6.referer

杜绝sql注入？

  1.使用addslashes等过滤

  2.使用pdo格式化

  3.严格限制输入的类型

## 写文件：

  into outfile into dumpfile

  一个可以写二进制文件，另外写了会有问题

  1.知道绝对路径

  2.当前用户需要拥有写入权限root

  3.secure-file-ptiv !=NULL

  4.需要使用单引号或者双引号

## 二次注入需要具备的两个条件：

  （1）用户向数据库插入恶意语句（即使后端代码对语句进行了转义，如mysql_escape_string、   mysql_real_escape_string,addslahes等等转义）

  （2）后端对从数据库中取出恶意数据没有进行过滤直接进行sql语句的拼接

# Sqlmap

sqlmap -u 目标url

​    -r REQUESTFILE从一个文件中载入的HTTP请求

​    -v  显示详细信息 默认为1

​       0、只显示python错误以及严重的信息。

​       1、同时显示基本信息和警告信息

​       2、同时显示debug信息

​       3、同时显示注入的payload

​       4、同时显示http请求

​       5、同时显示http响应头

​       6、同时显示Http响应页面 

​     --data="以post提交的参数，多个参数用&链接"

​     --delay   可以设定两个http请求间的延迟

​     --timeout  可以设定一个http请求超过对久判定为超时，默认是30秒

​     --p     指定你要测试的参数

​     --level 

​      共有五个等级，默认为1，sqlmap使用的payload可以在xml/payloads.xml中看到，自己也可以根据相应的格式添加自己的payload。

​       level>=2的时候就会测试HTTP Cookie。

​       level>=3的时候就会测试HTTP User-Agent/Referer头。

​       level=5 的时候会测试HTTP Host。

​     --risk   默认是1会测试大部分的测试语句，2会增加基于时间的测试语句，

​     --dbs    所有数据库

​     --tables -D 列出指定数据库的表  -T 指定表名  --columns 获取列  --count 获取有几行数据  -C 读取数据（例如-C "username,password"）   --dump 导出数据

--os-shell 做了哪些事情？

  1.判断url是否可以连接

  2.尝试看是否能够找到绝对路径id[]=1

  3.我们传递绝对路径 lines terminated by 来进行文件写入 写入的该文件具有上传文件的功能

  3a.会尝试访问路径C:/phpstudy/www/sqli-labs/Less-1 直接能够访问到该文件

  4.利用上传文件小马，再上传拥有命令执行能力的小马

  5.利用拥有命令执行能力的小马执行命令

  (1.判断url是否能够访问2.判断是否通过报错显示出绝对路径3.尝试使用terminated by来写入文件)

# 文件上传:

  在上传头像或者是其他文档的时候，我们通过抓包修改数据包或者其他手段上传一个脚本文件，这个脚本是带恶意代码的文件，比如一句话木马，如果上传成功就可以使用菜刀、CNIFE、蚁剑之类的工具链接这个脚本，从而达到控制网站的目的！

  1.基于前端的过滤 js  抓包 修改对应的后缀

  2.校验上传文件的类型 content-type

  3.基于黑名单的验证?

​    a) 大小写绕过

​    b) 双写 把特定字符串过滤为空

​    c) windows space . ::$DATA 末尾存在上述 会自动舍去

​    d) 使用特殊的后缀名 (.php3 .php4 .phtml )

​    e) .htaccess 可以控制当前目录下对特定名称特定类型的文件的解析方式

​    f) 解析漏洞?

​      1.apache 解析漏洞 当存在多后缀的时候,从右往左依次进行解析,

​        直到其能够正确的识别为止

​      2.iis 解析漏洞

​        6.0 

​          目录名中以.asa,.cer,.asp,cdx来进行结尾和包含的,该目录下的

​          所有文件均优先按照asp来进行解析

​        7.0/7.5

​          任意后缀名的文件/任意文件名.php

​      3.nginx 解析漏洞

​        任意后缀名的文件/任意文件名.php

​        很老版本的:

​          %00.php 可能可以按照php解析

​    g) %00截断 5.4 以下的版本

  4.生成图片木马 +include文件包含copy /b 1.jpg+2.php=3.jpg

  \5. 条件竞争 逻辑

## 对于文件上传漏洞的修复?

  1.白名单  严格限制能够上传文件的后缀

  2.对文件内容进行检测 一旦出现特定代码 直接上传失败 

# 文件包含

本地文件包含和远程文件包含造成漏洞的原因是一样的，当php.ini 中的配置选项allow_url_fopen和allow_url_include为 ON的话，则包含的文件可以是第三方 服务器中的文件，这样就形成了远程文件包含漏洞

include(),include_once(),require(),require_once()

include 报错继续执行

文件包含利用

  上传图片马，包含图片马GetShell

  读取网站源码以及配置文件

  包含日志文件GetShell

  包含session文件拿shell

伪协议

php://filter

php://input

data:text/plain

用法1：?file=data:text/plain,<?php 执行内容 ?>
 用法2：?file=data:text/plain;base64,编码后的php代码

  注意base64加密之后的代码,不能够有+号,否则会和url中的+编码冲突

file=zip://[压缩文件路径+压缩文件名]#[压缩文件内的子文件名]

文件包含修复：

  严格限制读取文件的后缀只允许包含特定的后缀

  严格限制﹒/\的使用不允许更改目录

  open_basedir限制只允许读取的目录

# XSS

  攻击者在网页中插入恶意的js脚本，由于网站没有对其过滤，当用户浏览时，就触发了js脚本，造成了xss攻击。Img，script，svg

1.反射型xss

  通常payload会出现在url或者请求包中，然后经过服务器的处理，payload

  最终会经由服务器返回给浏览器进行渲染

2.存储型xss

  往往需要将数据插入到对应的数据库中，并在特定的页面下从数据库中读取对应的内容

3.dom型xss

  无需经过服务器的处理 右键查看源码 找不到插入的payload

效果？

  获取管理员（特定用户的）cookie

  钓鱼

挖掘流程:

  1.找到一些可控的参数

  ⒉尝试输入标识符(213456'<>")独一无二的字符串右键查看源代码如果找不到:不存在xss或者dom型xss  如果存在的话:存储型反射型xss

修复建议:

  考虑使用过滤htmlspecialchars (,ENT_QUOTE)'转义

  httponly设置js不能访问某些cookie值 

# CSRF

登录之后,网站A赋予其一个cookie: A_name = user

紧接着,user去访问一个恶意网站evil www.evil.com

当访问的时候,服务器强制使得user的浏览器去向A发送

数据包.

当user的浏览器往A网站发送数据包时,其会检查是否保存了

对应的cookie,如果有,则会携带cookie发送请求包个网站A

对于网站A来说,当接收到user的浏览器发送过来的请求包,并且

携带上对应的cookie时,此时对于网站A来说,认为user发出的请求,

则会遵循客户的请求来执行相应的操作.

1.user需要登录或者cookie是生效的

⒉.要能够控制用户去访问特定的网站

3.存在csrf漏洞?

# SSRF

是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。

产生的原因：服务器端的验证并没有对其请求获取图片的参数（image=）做出严格的过滤以及限制，导致可以从其他服务器的获取一定量的数据

ssrf 对应的功能:

  1.读取内网中的文件源码

  2.判断服务是否开启http或者使用https协议

ssrf服务器端请求伪造

  1.file_get_contents

  2.curl_init curl_exec()

  3.fsockopen

ssrf csrf漏洞的区别?

  csrf客户端浏览器

  ssrf服务器端

  csrf 迫使用户在未意识到的情况下执行特定的操作

  ssrf 能够访问内网中的本无法访问到的资源

ssrf漏洞挖掘

  1.web功能上查找

​    a)通过url地址分享网页内容

​    b)转码服务

​    c)在线翻译

​    d)图片加载与下载

  2.从url关键字中寻找

​    Share、wap、url、link、src、source、target、u、3g、display、sourceURL、   imageURL、domain

​    归根到底,其实都是跟链接有关联的

绕过 短网址  xip.io

修复方案：

  1.统一错误信息，避免用户可以根据错误信息来判断远程服务器端口状态

  2.限制请求的端口为HTTP常用的端口，比如 80,443,8080,8088等 

  3.黑名单内网IP。

  4.禁用不需要的协议，仅仅允许HTTP和HTTPS.

  http://192.168.31.6/ssrf.php?img=file:///c://wwww//1.txt

  windows2008服务器+windows 2003服务器搭建

# XXE

Xml外部实体注入    常见在线翻译，留言板

XXE是XML外部实体注入攻击，XML中可以通过调用实体来请求本地或者远程内容，和远程文件保护类似，会引发相关安全问题，例如敏感文件读取。

当允许引用外部实体时，通过构造恶意内容，就可能导致任意文件读取、系统命令执行、内网端口探测、攻击内网网站等危害。

避免xxe

  1.升级php8

  2.libxml_disabl  e_entity_loader(true)

 3.XML解析库在调用时严格禁止对外部实体的解析。

# 代码执行

Eval  assert preg_replace /e $_GET[1]($_GET[2])

eval assert区别？

  eval语言构造器绝大部分情况下可以当作一个函数来进行使用可变函数不行echo 12345;后面只需跟上php代码 assert函数后面跟上函数

# 命令执行

应用在调用这些函数执行系统命令的时候，如果讲用户的输入作为 系统命令的参数拼接到命令行中，又没有过滤用户的输入的情况下， 就会造成命令执行漏洞。

system(args) 有回显

passthru(args)(有回显)

exec(args) （回显最后一行-必须echo输出）

shell_exec(args) （无回显-必须输出）

反引号：`` 无回显

popen(handle,mode)(无回显) 

proc_open('cmd','flag','flag')（无回显）

$process = proc_open('dir',$des,$pipes);

echo stream_get_contents($pipes[1]);

如何用命令执行连接蚁剑？

  system($_GET[1]);

  1=echo ^<?php eval($_POST[2]);?^> >1.php

disable_functions中禁用。

修复：

在进入命令执行的函数或方法之前，对参数进行过滤。

参数的值尽量使用引号包裹，并在拼接前调用addslashes进行转义。

exec() 函数中数据，避免用户可控。

# 变量覆盖

extract()

parse_str()import_request_variables

import_request_variables 函数可以在 register_global = off 时，把 GET/POST/Cookie 变量导入全局作用域中。

(PHP 4 >= 4.1.0, PHP 5 < 5.4.0)

# 反序列化漏洞

攻击者可以通过构造特定的恶意对象序列化后的流，让目标反序列化，从而达到自己的恶意预期行为，包括命令执行，甚至getshell等等。

  对象====>字符串

反序列化:

  字符串====>对象

方便在网络中进行传输

反序列时,需要依赖之前声明的类

反序列化生成的对象,将会依赖声明的类来拥有相应的方法

反序列化生成的对象,不依赖原有的构造方法.只会依赖我们提供的字符串====>反序列化有且只能控制属性我们只能控制生成的对象的属性的值不能控制调用的方法(poc链)

# 三次握手

第一次握手：[客户端](https://baike.baidu.com/item/客户端)发送syn(**表示建立连接**)包(syn=j)到服务器，并进入SYN_SEND状态，等待服务器确认；[第二次握手](https://baike.baidu.com/item/第二次握手)：服务器收到syn包，必须确认客户的syn（ack=j+1），同时自己也发送一个SYN包（syn=k），即SYN+ACK包，此时服务器进入[SYN_RECV](https://baike.baidu.com/item/SYN_RECV)状态；第[三次握手](https://baike.baidu.com/item/三次握手)：[客户端](https://baike.baidu.com/item/客户端)收到服务器的SYN+ACK包，向服务器发送确认包ACK(ack=k+1)，此包发送完毕，[客户端](https://baike.baidu.com/item/客户端)和服务器进入ESTABLISHED状态

# WEB渗透流程

## 信息收集

子域名layer，oneforall，subDomainBrute，在线查询

目录爆破，御剑，7kbscan，dirbuster

nmap看开放的端口

robots.txt 

cms 在线，godeye ，云悉指纹  ， whatweb

在线查询cdn，多ping网站  微步在线，站长之家

  cdn如何绕过?

​    1.内部邮箱地址

​    2.phpinfo phpstudy等默认展示页面泄露ip

​    3.历史cdn

​      微步在线

​    4.子域名

​    5.ddos

  6.通过搜索引擎去寻找

Waf识别

nmap -p 80 --script=http-waf-fingerprint www.baidu.com

wafw00f

  wafw00f https://www.xxx.com/

## 漏洞扫描

根据信息收集内容，对他的框架去搜索有没有通用漏洞，然后使用工具awvs，xray+bp进行扫描，对已知的漏洞尝试利用，尽量getshell，

提权，内网

3.最后将使用的工具，payload整理好，攥写渗透测试报告

 

# MySQL提权

  mysql提权的前提:

​    root并且对特定的目录拥有写的权限(--secure-file-priv != NULL)

  1.读取配置文件

  2.webshell data /mysql/user三个文件尝试导出文件导入到本地数据库

## Udf提权

指定一个数据库(mysql)

  定义一个变量@a,该内容为dll的值,以16进制的形式进行拼接

  在该数据库下创建一张表(ghost)，拥有一个字段,且数据类型为longblob

  向该表中插入变量@a的值

  读取表中的值,写入lib\plugin目录下,从而创建一个dll文件

  从dll文件中读取想要执行的函数,进行调用

udf反弹提权

## Mof提权

mof 提权利用了 c:/windows/system32/wbem/mof/ 目录下的 nullevt.mof 文件，MOF文件每五秒就会执行一次，而且是使用系统权限.

如果我们通过mysql使用into outfile 将文件写入/wbme/mof，然后系统每隔五秒就会执行一次我们上传的MOF。MOF当中有一段是vbs脚本，我们可以通过控制这段vbs脚本的内容让系统执行命令，进行提权。

 

# SQL server提权

\1. 差异备份

\2. Xp_cmdshell

\3. Sp_oacreate

\4. 沙盒提权

\5. Sethc.exe替换

 

# Linux提权

1.利用提权辅助脚本枚举可能没有打的补丁,尝试利用exp提权

2.利用/etc/passwd文件来提权

3.读取配置文件，看是否密码存在复用 config.php .....

4.sudo提权 当前用户在输入自己得密码之后，能够以特定用户(root)来执行特定的指令etc/sudoers

5.计划任务提权 如果知道高权限用户会在特定的时间内反复得执行某些脚本，脚本当前低权限用户可控，此时可以通过控制执行脚本得内容来进行提权

脏牛提权

大于2.6.22版本 (2007年发行，到2016年10月18日修复)

危害：低权限的用户可利用这一漏洞在本地进行提权

原理：linux内核的子系统在处理写入时复制至产生了竞争条件，恶意用户可利用此漏洞来获取高权限，对只读内存映射进行访问。

竞争条件:指的是任务执行顺序异常，可导致应用奔溃，或令攻击者有机可乘，进一步执行其他代码，利用这一漏洞，攻击者可在其目标系统提升权限，甚至可能获取到root权限。

 

# Window提权

使用提权辅助工具，配合msf，也可以使用cs在要攻击的主机上线，可以进程迁移，添加服务，添加启动项，添加计划任务。

 

# 内网渗透

  提权后，使用cs或者代理工具ew，frp，lcx，venom，在线ngrok

 

# Linux服务器加固

\1. 阻止普通用户关机

\2. 设置用户密码过期时间

\3. 强制用户下次登录必须修改密码

\4. 账号锁定

\5. 给文件加锁

 

# Windows应急响应

常见的应急响应事件分类：

web入侵：网页挂马、主页篡改、Webshell

系统入侵：病毒木马、勒索软件、远控后门

网络攻击：DDOS攻击、DNS劫持、ARP欺骗

检查系统账号、检查异常端口、进程、检查启动项、计划任务、服务、检查系统相关信息、日志分析

  判断是否有新增的用户net user lusrmgr.msc	 判断是否存在隐藏的用户ddun扫描	  查看当前用户 query user

查看是否存在弱口令,询问管理员，看端口是否对公网开放

  判断是否对外开放的敏感端口Nmap –p 1-65535 –A –T4 10.0.0.0/24

  3389，22，3306等

查看开放端口netstat -ano优先查看外连ip ESTABLISHED	   进程定位 tasklist | findstr pid	 

使用D盾进程查看，对可疑进程找到目标文件进行在线检测	微步在线.....

启动项 msconfig 也可以任务管理器 查看注册表

  检查日志eventvwr.msc 筛选4624登录成功，4625登录失败，4670创建用户

  检查可疑目录 开始->运行，输入%UserProfile%\Recent，分析最近打开分析可疑文件

  病毒查杀 D盾，360，火绒，卡巴斯基，bitdefender，安全狗等等

  webshell查杀 使用网站后门检测工具

# Linux应急响应

  先使用who，w，uptime等常用命令查看登录用户信息，然后查看/etc/passwd文件有没有弱密码或者无密码，/etc/shadow看是否有增加新用户，将可疑用户禁用，再查看/etc/sudoers看是否有权限配置错误

  History 查看历史命令在查看/home/.bash_history，看普通用户历史命令

  Netstat查看已确立连接的IP及端口

  ps aux | grep pid定位可疑进程所在位置(可以将可疑文件进行在线上传检测)

​    检查开机启动项

​    检查定时任务/etc/cron.d

​    检查可疑目录/tmp，和隐藏文件

​    检查日志文件/var/log

​    使用lastlog看所有用户最后一次登录信息

​    Lastb查看所有用户错误登录信息

  最后可以安装杀毒软件clamav、chkrootkit、rhunter

# Web应急响应

Windows星图日志分析

Linux goaccess   Goaccess -f ./access.log -a

 

# OWASP 10

\1. 注入

\2. 失效的身份认证和会话管理

Cookie或session失效的情况下可以使用

\3. 跨站脚本XSS

在web页面中插入恶意代码

\4. 失效访问控制

对于通过认证的用户没有进行限制，攻击者可以利用这些缺陷访问未授权的功能和数据

\5. 安全配置错误

应用程序，框架，web服务器，默认设置是不安全的，需要进行配置，要及时更新和维护

\6. 敏感信息泄露

Web应用程序和api没有正确保护敏感数据，攻击者窃取或篡改数据

\7. 攻击检测与防护不足

\8. 跨站请求伪造csrf

\9. 使用含有已知漏洞的组件，比如框架，软件模块

10.未受保护的api 

手机app与浏览器中的JavaScript和某api连接，这些api通常是不受保护的

 

# 免杀

1.变量覆盖配合全局变量

2.类配合魔术方法

3.回调函数以及变量函数

4.反序列化

5.trait特性

 

# Jboss

漏洞原理：JBoss AS 4.x及之前版本中，JbossMQ实现过程的JMS over HTTP Invocation Layer的HTTPServerILServlet.java文件存在反序列化漏洞，远程攻击者可借助特制的序列化数据利用该漏洞执行任意代码。

# shiro

漏洞原理：Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。在服务端对rememberMe的cookie值，先base64解码然后AES解密再反序列化，就导致了反序列化RCE漏洞。

# Weblogic

反序列化处理输入信息时存在缺陷，攻击者通过发送精心构造的恶意 HTTP 请求，即可获得目标服务器的权限，在未授权的情况下远程执行命令。

# 逻辑漏洞

1. 任意用户密码修改

三佳购物

2. 越权访问，垂直，水平

Sessionid覆盖

3. 数据遍历

登录页面用户不存在，可以脚本跑

4. 订单金额修改

主要原因就是在支付成功以后没有在对数据包中的金额和商品的金额进行hash匹配

# 绕WAF

大小写、双写、内联注释、编码、等价函数替换、分块传输

# 文件上传绕安全狗

\1. 单双引号

\2. 回车绕过

\3. ==多等号

\4. 文件内容溢出

\5. Filename= ;放一个空的

\6. %00截断(对版本有要求，这个没成功过)

#  常用端口

21 FTP    * 443   HTTPS

22 SSH    * 1433 MS SQL Server

23 Telnet   * 1521 Oracle

25 SMTP    * 3306 MySql

53 DNS    * 3389 RDP

80 HTTP   * 6379 redis

# kali目录

bin 执行程序
boot 引导程序
dev 设备目录
etc 配置文件
home 用户主目录（但在kali中主目录在root）
lib 库文件
media 挂载外接存储
mnt 挂载外接（以前发行版用的）
opt 应用程序
proc 内存中（当前配置参数）
root 主目录
sbin 执行程序（只有管理员有权执行）
tmp 临时目录
usr 执行程序 共享文件
var 日志 邮件（经常变化的内容）

# ARP欺骗和嗅探的原理

计算机之间通信通过MAC地址，但对获得得MAC地址不做验证，直接记录，所以可以发送ARP包达到欺骗得目的  

# MSF模块

  Msfvenom生成payload

  /multi/handler  监听

smb_version 模块（文件共享，端口号445）

ssh_version 模块

ftp_version FTP主机扫描

ms16075烂土豆

ms17-010永恒之蓝

# HTTP-Only读取cookie信息，如何绕过

Http Trace攻击就可以将你的Header里的Cookie回显出来，利用Ajax或者flash就可以完成这种攻击；或者配置或者应用程序上可能Bypass，比如header头的泄漏

1.phpinfo	其中$_SERVER[“HTTP_COOKIE”]

2.框架钓鱼

# Redis

  端口6379

  无关系数据库，最大特点在内存上读取数据，快

  写shell  /var/www/html/

  写计划任务 /root/spool/cron/

  写ssh /root/.ssh/

# 黄金白银票据

  客户端先与AS交互再去AD域账户数据库，然后返回TGT（krbtgt NTLM Hash），这就是金票，TGT再去访问TGS返回ST（服务账号 NTLM Hash），在带着ST访问server服务器。

  伪造金票就是不用去访问AS，要与KDC得TGS进行交互

  伪造银票可以直接访问server。

  金票可以获取任意Kerberos(身份认证)的访问权限，银票只有一些特定得服务。
