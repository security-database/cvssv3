CVSS Calculator v3 preview 2
===============

Common Vulnerability Scoring System Version 3.0
---------------------------------

Common Vulnerability Scoring System (CVSS) is a free and open industry standard for assessing the severity of computer system security vulnerabilities. It is under the custodianship of NIST. It attempts to establish a measure of how much concern a vulnerability warrants, compared to other vulnerabilities, so efforts can be prioritized. The scores are based on a series of measurements (called metrics) based on expert assessment. The scores range from 0 to 10. Vulnerabilities with a base score in the range 7.0-10.0 are High, those in the range 4.0-6.9 as Medium, and 0-3.9 as Low.

License
--------
This piece of software is under [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

PHP Class
--------

Initialization
--------
To utilize this class, first import MysqliDb.php into your project, and require it.
```php
include_once('cvss.class.php');
```

After that, create a new vector.
```php
try {

	$cvss = new \CVSSv3\Cvss();
	$cvss->register("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N/E:P/RL:W/CR:L/IR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L");

} catch (Exception $e) {
	print $e->getCode()." : ".$e->getMessage();
}
```

You can now  get some informations :

Get scores of every piece of the vector (array());
```php
	print_r($cvss->scores);

```

Get sub scores used in formula (array());
```php
	print_r($cvss->calcul);
```

Get Formula with detail
```php
	print_r($cvss->formula);
```

Get the vector
```php
print_r($cvss->vector);
```
