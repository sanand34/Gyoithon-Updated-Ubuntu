# **GyoiThon**: **Next generation penetration test tool**


## Overview
GyoiThon is **Intelligence Gathering tool** for Web Server.  

GyoiThon execute **remote access** to target Web server and **identifies product operated on the server** such as CMS, Web server software, Framework, Programming Language etc,. And, it can **execute exploit modules** to identified products using Metasploit. GyoiThon **fully automatically execute** above action.  

GyoiThon's main features are following.  

 * Remote access/Fully automatic  
 GyoiThon can **fully automatically** gather the information of target Web server using only **remote access**. You only execute GyoiThon once for your operation.  

 * Non-destructive test  
 GyoiThon can gather information of target Web server using **only normally access**.  
 But, when you use a part of option, GyoiThon execute abnormally access such as sending exploit modules.  

 * Gathering various information  
 GyoiThon has various intelligence gathering engines such as Web crawler, Google Custom Search API, Censys, explorer of default contents, examination of cloud services etc,. By analyze gathered information using **strings pattern matching** and **machine learning**, GyoiThon can identify **product/version/CVE number** operated on the target web server, **unnecceary html comments**/**debug messages**, **login page** etc,.  

 * Examination of real vulnerability  
 GyoiThon can execute exploit modules to identified products using Metasploit.  
 As a result, it can **examine real vulnerability of target web server**.  



## <a name='Installation'>Installation</a>

1. Get python3-pip.  
```
root@kali:~# apt-get update
root@kali:~# apt-get install python3-pip
```

2. install required python packages.  
```
root@kali:~# cd GyoiThon
root@kali:~/GyoiThon# pip3 install -r requirements.txt
root@kali:~/GyoiThon# apt install python3-tk
```

3. Edit config.ini of GyoiThon.  
You have to edit your `config.ini`.  
More information is Usage.  

## <a name='Usage'>Usage</a>


```
usage:
    .\gyoithon.py [-s] [-m] [-g] [-e] [-c] [-p] [-l --log_path=<path>] [--no-update-vulndb]
    .\gyoithon.py [-d --category=<category> --vendor=<vendor> --package=<package>]
    .\gyoithon.py [-i]
    .\gyoithon.py -h | --help
options:
    -s   Optional : Examine cloud service.
    -m   Optional : Analyze HTTP response for identify product/version using Machine Learning.
    -g   Optional : Google Custom Search for identify product/version.
    -e   Optional : Explore default path of product.
    -c   Optional : Discover open ports and wrong ssl server certification using Censys.
    -p   Optional : Execute exploit module using Metasploit.
    -l   Optional : Analyze log based HTTP response for identify product/version.
    -d   Optional : Development of signature and train data.
    -i   Optional : Explore relevant FQDN with the target FQDN.
    -h --help     Show this help message and exit.
```

### Preparation.  
1. Edit target file `host.txt`.  
You have to write target web server to the `host.txt`.  
Writting format is `protocol FQDN(or IP address) Port Crawling_root_path`.  

* Example.  
```
https gyoithon.example.com 443 /
```

If you want to indicate multiple target information, you have to write below.  

```
https gyoithon.example.com 443 /
http 192.168.220.129 80 /vicnum/
https www.example.com 443 /catalog/
```

| Note |
|:-----|
| You insert `/` at the beginning and end of Root Path. |

2. Edit configuration file `config.ini`.  
Parameters to be changed by the user are defined in the setting file `config.ini`.  
If you want to change parameters, edit `config.ini`.  
### Execution of GyoiThon.  
#### <a name='default_mode'>1. Default mode.</a>  
```
root@kali:~/GyoiThon# python3 gyoithon.py
```

The default mode gathers following minimum information.  

 1. Gathering of HTTP responses by Web crawling.  
 2. Identification of product/version using string pattern matching.  
 3. Examination of CVE number (from NVD) for identified products.  
 4. Examination of unneccesary HTML/JavaScript comments.  
 5. Examination of unneccesary debug messages.  
 6. Examination of login pages.  

 * Crawling setting  
 GyoiThon uses `Scrapy` that Python's library.  
 By change the parameters in `config.ini`, you can change setting of Scrapy.  

 |Category|Parameter|Description|
 |:----|:----|:----|
 |Spider|depth_limit|Maximum depth of crawling. Default value is `2` layer. |
 ||delay_time|Delay time of crawling. Default value is `3` (sec). |
 ||time_out|Spider close option. Timeout of crawling. Default value is `600` (sec). |
 ||item_count|Spider close option. Maximum items. Default value is `300`. |
 ||page_count|Spider close option. Maximum items per page. Default value is `0` (no limit). |
 ||error_count|Spider close option. Maximum errors. Default value is `0` (no limit). |

 * Examination speed setting  
 The examination number and HTTP response size greatly affect examination times.   
 By change the parameters in `config.ini`, you can adjust examination speed.  

 |Category|Parameter|Description|
 |:----|:----|:----|
 |Common|max_target_url|Maximum examination URL number. If the URL number gathered by Web Crawling exceeds this parameter value, excess URL number is discarded. Default value is `100`. `0` is unlimited.|
 ||max_target_byte|Maximum examination response size. If the response size exceeds this parameter value, excess response size is discarded. Default value is `10000` byte. `0` is unlimited.|
 ||scramble|The URL list gathered by Web crawling is randomly ordered. Default value is `1` (validity). `0` is invalid.|

 | Note |
 |:-----|
 | The examination speed and accuracy are trade-off. |



#### 2. Machine Learning analysis mode.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -m
```

By add `-m` option, GyoiThon identifies products/version using Machine Learning (Naive Bayes) in addition to default mode.  



#### <a name='generating_sig'>10. Generating signature/train data mode</a>.  
```
root@kali:~/GyoiThon# python3 gyoithon.py -d --category=CMS --vendor=joomla! --package=Joomla!@3.9.4@_origin.tar.zip
```

By add `-d` option, GyoiThon generates signatures/train data for detecting Web products operated on the target Web Server.  
The options is following.  

|Option|Description|Example|
|:----|:----|:----|
|--category|Product's category in signature/train data.|`OS` or `WEB` or `FRAMEWORK` or `CMS`. |
|--vendor|Product's vendor name in signature/train data. |`wordpress`, `joomla!`, `drupal`.|
|--package|Importing target package file name. You have to separate three fields that product name, version and extension using `@`.|`WordPress@4.9.8@.tar.gz`, `Joomla!@3.9.4@_origin.tar.zip`, `Drupal@8.6.3@.tar.gz`. |

### Check report.  
After finished execution of GyoiThon, reports of each target are generated to the following path.    

```
root@kali:~/GyoiThon/report# ls
gyoithon_report_192.168.220.129_80_1082018338.csv
gyoithon_report_192.168.220.129_80_bodgeit.csv
gyoithon_report_192.168.220.129_80_cyclone.csv
gyoithon_report_192.168.220.129_80_vicnum.csv
gyoithon_report_192.168.220.129_80_WackoPicko.csv
gyoithon_censys_report_www.gyoithon.example.com_443_test.csv
```

GyoiThon generates following two types report.  

 * `gyoithon_report_target FQDN(or IP address)_Port number_Root Path.csv`.  
 This is main report that mainly including product name, version, cve etc,.  
 Report format is `gyoithon_report_target FQDN(or IP address)_Port number_Root Path.csv`.  
 Each column's detail is following.  

|Column|Description|Example|
|:----|:----|:----|
|fqdn|FQDN of target web server.|`www.gyoithon.example.com`|
|ip_addr|IP address of target web server.|`192.168.220.129`|
|port|Port number of target web server.|`80`|
|cloud_type|Cloud service name (Azure or AWS or GCP or Unknown).|`AWS`|
|method|Examination way of GyoiThon.|`Crawling`|
|url|Accessed URL.|`http://192.168.220.129:80/WackoPicko/admin/index.php?page=login`|
|vendor_name|Vendor name of identified products.|`apache`|
|prod_name|Identified products.|`http_server`|
|prod_version|Version of identified products.|`2.2.14`|
|prod_trigger|Trigger of identified products.|`Apache/2.2.14`|
|prod_type|Product category (Web or CMS or Framework etc..).|`Web`|
|prod_vuln|CVE number according to identified products (desc CVSS score).|`CVE-2017-3167, CVE-2017-3169, CVE-2017-7668` ...|
|origin_login|Login page is existing or not (Log: Analysis using Machine Leaerning, Url: Analysis using string pattern matching in URL.|`Log : 37.5 %\nUrl : 100.0 %`|
|origin_login_trigger|Trigger of identifed login page.|`Log : name",<input type="password"\nUrl : login`|
|wrong_comment|Identified unnecessary comments.|`パスワードは「password1234」です。`|
|error_msg|Identified unnecessary debug messages.|`Warning: mysql_connect() ..snip.. in auth.php on line 38`|
|server_header|Server header of HTTP response.|`Server: Apache/2.2.14 (Ubuntu) mod_mono/2.4.3 PHP/5.3.2`|
|log|Path of raw data.|`/usr/home/~snip~/http_192.168.220.129_80_20181112170525765.log`|
|date|Examination date.|`2018/11/12  17:05:25`|

 * `gyoithon_censys_report_target FQDN(or IP address)_Port number_Root Path.csv`.  
 This is search result report using Censys that including open ports, certification information etc,.  
 Report format is `gyoithon_censys_report_target FQDN(or IP address)_Port number_Root Path.csv`.  
 Each column's detail is following.  

|Column|Description|Example|
|:----|:----|:----|
|fqdn|FQDN of target web server.|`www.gyoithon.example.com`|
|ip_addr|IP address of target web server.|`192.168.220.129`|
|category|Information category.|`Server Info` or `Certification Info`|
|open_port|Open web port.|`443`|
|protocol|Protocol of open web port.|`https`|
|sig_algorithm|Signature algorithm of certification.|`SHA256-RSA`|
|cname|Common name of certification.|`www.gyoithon.example.com`|
|valid_start|Validity start date of certification.|`2018-08-15T00:00:00Z`|
|valid_end|Validity end date of certification.|`2019-09-16T12:00:00Z`|
|organization|Organization name of certification.|`GyoiThon coorporation, Inc.`|
|date|Examination date.|`2018/11/22  11:19:36`|

| Note |
|:-----|
| Because Censys needs several days to several weeks to survey the entire Internet, the information obtained from Censys may not be up-to-date.|

## <a name='Tips'>Tips</a>
### 1. How to manually add new signature (string matching patterns).  
`signatures` path includes below files.  

```
root@kali:~/GyoiThon/signatures/ ls
signature_product.txt
signature_default_content.txt
signature_search_query.txt
signature_comment.txt
signature_error.txt
signature_page_type_from_url.txt
```

#### `signature_product.txt`  
This is string matching patterns for identification of product in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1@field2@field3@field4@field5
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Required|1|Product Category.|`CMS`|
|Required|2|Vendor name.|`drupal`|
|Required|3|Product name.|`drupal`|
|Optional|4|Version binded with this signature.|`8.0` |
|Required|5|Regex of identifying product.|`.*(X-Generator: Drupal 8).*`|

If you don't need optional field, you must set `*` to this field.  

* Example  
```
CMS@wordpress@wordpress@*@.*(WordPress ([0-9]+[\.0-9]*[\.0-9]*)).*
CMS@drupal@drupal@8.0@.*(X-Generator: Drupal 8).*
```

| Note |
|:-----|
| If you want to extract product version, you write two regex groups (**the second regex is used for version extraction**). |

#### `signature_default_content.txt`  
This is string matching patterns for identification of product in <a name='explore_contents_mode'>Exploration of default contents mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1@field2@field3@field4@field5@field6@field7@field8
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Required|1|Product Category.|`CMS`|
|Required|2|Vendor name.|`sixapart`|
|Required|3|Product name.|`movabletype`|
|Optional|4|Version binded with this signature.|`*` |
|Required|5|Explore path|`/readme.html`|
|Optional|6|Regex of to confirm product.|`.*(Movable Type).*`|
|Optional|7|Regex of identifying version.|`(v=([0-9]+[\.0-9]*[\.0-9]*))`|
|Required|8|Login page or not.|Login page is `1`, Not login page is `0`|

If you don't need optional field, you must set `*` to this field.  

* Example  
```
Web@apache@http_server@*@/server-status@*@Version:.*(Apache/([0-9]+[\.0-9]*[\.0-9]*))@0
CMS@sixapart@movabletype@*@/readme.html@.*(Movable Type).*@(v=([0-9]+[\.0-9]*[\.0-9]*))@0
```

| Note |
|:-----|
| If you want to extract product version, you write two regex groups (**the second regex is used for version extraction**). |

| Note |
|:-----|
| If GyoiThon cannot confirm the product by just `Explore path`, you need to indicate the `Regex of to confirm product` field. GyoiThon accesses the URL that `Explore path` and examines the HTTP response using `Regex of to confirm product`. If this regex matches, GyoiThon judges that the product exists. |

#### `signature_search_query.txt`  
This is Google Custom Search query for identification of product in <a name='google_hacking_mode'>Google Hacking mode</a>.  
If you want to add new query, you have to write it such following format.   

```
Format: field1@field2@field3@field4@field5@field6@field7@field8
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Optional|1|Product Category.|`CMS`|
|Optional|2|Vendor name.|`sixapart`|
|Optional|3|Product name.|`movabletype`|
|Optional|4|Version binded with this signature.|`*` |
|Required|5|Google Custom Search query|`inurl:/readme.html`|
|Optional|6|Regex of to confirm product.|`.*(Movable Type).*`|
|Optional|7|Regex of identifying version.|`(v=([0-9]+[\.0-9]*[\.0-9]*))`|
|Optional|8|Login page or not.|Login page is `1`, Not login page is `0`|

If you don't need optional field, you must set `*` to this field.  

* Example  
```
Web@apache@http_server@*@inurl:/server-status@*@Version:.*(Apache/([0-9]+[\.0-9]*[\.0-9]*))@0
CMS@sixapart@movabletype@*@inurl:/readme.html@.*(Movable Type).*@(v=([0-9]+[\.0-9]*[\.0-9]*))@0
*@*@*@*@filetype:bak@*@*@0
```

| Note |
|:-----|
| If you want to extract product version, you write two regex groups (**the second regex is used for version extraction**). |

| Note |
|:-----|
| If GyoiThon cannot confirm the product by just `Google Custom Search query`, you need to indicate the `Regex of to confirm product` field. GyoiThon accesses the URL included in the execution result of Google Custom Search API and examines the HTTP response using `Regex of to confirm product`. If this regex matches, GyoiThon judges that the product exists. |

#### `signature_comment.txt`  
This is string matching patterns for identification of unnecessary comments in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Regex of unnecessary comment.|

* Example  
```
(user\s*=|[\"']user[\"']\s*:|user_id\s*=|[\"']user_id[\"']\s*:|id\s*=|[\"']id[\"']\s*:)
(select\s+[\s\r\n\w\d,\"']*\s+from)
```

#### `signature_error.txt`  
This is string matching patterns for identification of unnecessary debug message in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Regex of unnecessary debug message.|

* Example  
```
(ORA-[0-9a-zA-Z\.])
(fail|error|notice|parse|warning|fatal)[^\n]*line[^\n]*[0-9]+
```

#### `signature_page_type_from_url.txt`  
This is string matching patterns for URL based identification of page type in <a name='default_mode'>default mode</a>.  
If you want to add new string matching pattern, you have to write it such following format.   

```
Format: field1@field2
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Page type.|
|Required|2|Regex of identifying page type.|

* Example  
```
Login@.*(login|log_in|logon|log_on|signin|sign_in).*
```

|Note|
|:---|
|Above vendor name and product name must be match a name in [CPE format](https://en.wikipedia.org/wiki/Common_Platform_Enumeration).|

### 2. How to manually add learning data.  
`modules/train_data/` path includes two train data for Machine Learning.  

```
root@kali:~/GyoiThon/modules/train_data/ ls
train_cms_in.txt
train_page_type.txt
```

#### `train_cms_in.txt`  
This is train data for Machine Learning analysis in <a name='machine_learning_mode'>Machine Learning mode</a>.  
If you want to add new train data, you have to write it such following format.   

```
Format: field1@field2@field3@field4
```

|Type|Field#|Description|Example|
|:---|:---|:---|:---|
|Required|1|Vendor name.|`joomla`|
|Required|2|Product name.|`joomla\!`|
|Optional|3|Version binded with this train data.|`*` |
|Required|4|Feature of product expressed by regex.|`(Set-Cookie: [a-z0-9]{32}=.*);`|

If you don't need optional field, you must set `*` to this field.  

* Example  
```
joomla@joomla\!@*@(Set-Cookie: [a-z0-9]{32}=.*);
joomla@joomla\!@*@(Set-Cookie: .*=[a-z0-9]{26,32});
heartcore@heartcore@*@(Set-Cookie:.*=[A-Z0-9]{32});.*
heartcore@heartcore@*@(<meta name=["']author["'] content=["']{2}).*
```

|Note|
|:---|
|Above vendor name and product name must be match a name in [CPE format](https://en.wikipedia.org/wiki/Common_Platform_Enumeration).|

#### `train_page_type.txt`  
This is train data for identifying page type usin Machine Learning in <a name='default_mode'>default mode</a>.  
If you want to add new train data, you have to write it such following format.   

```
Format: field1@field2
```

|Type|Field#|Description|
|:---|:---|:---|
|Required|1|Category.|
|Required|2|Feature of page expressed by regex.|

* Example  
```
Login@.*(<input.*type=[\"']text[\"'].*name=[\"']user|uid|username|user_name|name[\"']).*>
Login@.*(<input.*type=[\"']password[\"']).*>
```

