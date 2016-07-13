##PHP Class for CVSS v3 Calculator

[![Build Status](https://travis-ci.org/security-database/cvssv3.svg?branch=master)](https://travis-ci.org/security-database/cvssv3)

[![Latest Stable Version](https://poser.pugx.org/security-database/cvss/version)](https://packagist.org/packages/security-database/cvss)
[![Total Downloads](https://poser.pugx.org/security-database/cvss/downloads)](https://packagist.org/packages/security-database/cvss)
[![Latest Unstable Version](https://poser.pugx.org/security-database/cvss/v/unstable)](//packagist.org/packages/security-database/cvss)
[![License](https://poser.pugx.org/security-database/cvss/license)](https://packagist.org/packages/security-database/cvss)

###Common Vulnerability Scoring System Version 3.0

Common Vulnerability Scoring System (CVSS) is a free and open industry standard for assessing the severity of computer system security vulnerabilities. It is under the custodianship of NIST. It attempts to establish a measure of how much concern a vulnerability warrants, compared to other vulnerabilities, so efforts can be prioritized. The scores are based on a series of measurements (called metrics) based on expert assessment. The scores range from 0 to 10. Vulnerabilities with a base score in the range 7.0-10.0 are High, those in the range 4.0-6.9 as Medium, and 0-3.9 as Low. Class try to follow PSR2 standard except for some 120chars on formula.

###License
This piece of software is under [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

###PHP Class

####Initialization

Could be composer:

```php
composer require security-database/cvss
```

or traditional include class into your project, and include it.
```php
include_once('Cvss3.php');
```

After that, create a new vector.
```php
try {
	$cvss = new SecurityDatabase\Cvss\Cvss3();
	$cvss->register("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N/E:P/RL:W/CR:L/IR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L");

} catch (Exception $e) {
	print $e->getCode()." : ".$e->getMessage();
}
```

####Usage
You can now get some informations :

Get scores of every piece of the vector (array());
```php
print_r($cvss->scores);
/*
Array
(
    [AV] => 0.85
    [AC] => 0.44
    [PR] => 0.27
    [UI] => 0.62
    [C] => 0.22
    [I] => 0.22
    [A] => 0
    [E] => 0.94
    [RL] => 0.97
    [CR] => 0.5
    [IR] => 0.5
    [MAV] => 0.62
    [MAC] => 0.44
    [MPR] => 0.62
    [MUI] => 0.85
    [MC] => 0.22
    [MI] => 0.22
    [MA] => 0.22
    [RC] => 1
    [AR] => 1
)*/
```

Get sub scores used in formula (array());
```php
print_r($cvss->calcul);
/*
Array
(
    [ISCbase] => 0.3916
    [ISC] => 2.514072
    [ESC] => 0.514634472
    [BS] => 3.1
    [TS] => 2.9
    [MESC] => 1.181753232
    [ISCmodified] => 0.382162
    [MISS] => 2.45348004
    [ES] => 3.4
)
*/
```

Get Formula with detail
```php
print_r($cvss->formula);

/*
Array
(
    [ISCbase] => 1 - ( ( 1 - 0.22 ) * ( 1 - 0.22 ) * ( 1 - 0 ) )
    [ISC] => 6.42 * 0.3916
    [ESC] => 8.22 * 0.85 * 0.44 * 0.27 * 0.62
    [BS] => round_up( min( 10 , 2.514072 + 0.514634472 ) )
    [TS] => round_up( 3.1 * 0.94 * 0.97 * 1)
    [MESC] => 8.22 * 0.62 * 0.44 * 0.62 * 0.85
    [ISCmodified] => min( 0.915, 1 - ( ( 1 - 0.22 * 0.5 ) * ( 1 - 0.22 * 0.5 ) * ( 1 - 0.22 * 1 ) ) )
    [MISS] => 6.42 * 0.382162
    [ES] => round_up(min(10 , (2.45348004 + 1.181753232 ) * 0.94 * 0.97 * 1),1)
) */
```

Get the vector
```php
print $cvss->vector;

/* return a string :
   CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N/E:P/RL:W/CR:L/IR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L
*/
```

####Contribute
If you found any error on the class, please contact us at "info at security-database.com"