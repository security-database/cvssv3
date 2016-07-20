##PHP Class for CVSS v3 Calculator

[![Build Status](https://travis-ci.org/security-database/cvssv3.svg?branch=master)](https://travis-ci.org/security-database/cvssv3)

[![Latest Stable Version](https://poser.pugx.org/security-database/cvss/version)](https://packagist.org/packages/security-database/cvss)
[![Total Downloads](https://poser.pugx.org/security-database/cvss/downloads)](https://packagist.org/packages/security-database/cvss)
[![Latest Unstable Version](https://poser.pugx.org/security-database/cvss/v/unstable)](//packagist.org/packages/security-database/cvss)
[![License](https://poser.pugx.org/security-database/cvss/license)](https://packagist.org/packages/security-database/cvss)

###Version
####1.3.0
- Fix - Errors on calculation, specific on Modified Scope
- Fix - Modified scores -> weight (float)
- Rework - Modified scores with normalized names - easy to read the code now
- Added - Multi language Label

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

Get weight of every piece of the vector (array());
```php
print_r($cvss->weight);
/*
array (size=20)
  'AV' => float 0.85
  'AC' => float 0.44
  'PR' => float 0.27
  'UI' => float 0.62
  'C' => float 0.22
  'I' => float 0.22
  'A' => float 0
  'E' => float 0.94
  'RL' => float 0.97
  'CR' => float 0.5
  'IR' => float 0.5
  'MAV' => float 0.62
  'MAC' => float 0.44
  'MPR' => float 0.62
  'MUI' => float 0.85
  'MC' => float 0.22
  'MI' => float 0.22
  'MA' => float 0.22
  'RC' => float 1
  'AR' => float 1
*/
```

Get sub scores used in scores (array());
```php
print_r($cvss->scores);
/*
array (size=9)
  'impactSubScoreMultiplier' => float 0.3916
  'impactSubScore' => float 2.514072
  'exploitabalitySubScore' => float 0.514634472
  'baseScore' => float 3.1
  'temporalScore' => float 2.9
  'envModifiedExploitabalitySubScore' => float 1.181753232
  'envImpactSubScoreMultiplier' => float 0.382162
  'envModifiedImpactSubScore' => float 2.45348004
  'envScore' => float 3.4
*/
```

Get sub scores with label (en_US) used in scoresLabel (array());
```php
print_r($cvss->scores);
/*
array (size=9)
  'Impact SubScore Multiplier' => float 0.3916
  'impact SubScore' => float 2.514072
  'Exploitabality Sub Score' => float 0.514634472
  'Base Score' => float 3.1
  'Temporal Score' => float 2.9
  'Environmental Modified Exploitabality SubScore' => float 1.181753232
  'Environmental Impact SubScore Multiplier' => float 0.382162
  'Environmental Modified Impact SubScore' => float 2.45348004
  'Environmental Score' => float 3.4
*/
```


Get Formula with detail
```php
print_r($cvss->formula);

/*
    array (size=9)
      'impactSubScoreMultiplier' => string '1 - ( ( 1 - 0.22 ) * ( 1 - 0.22 ) * ( 1 - 0 ) )' (length=47)
      'impactSubScore' => string '6.42 * 0.3916' (length=13)
      'exploitabalitySubScore' => string '8.22 * 0.85 * 0.44 * 0.27 * 0.62' (length=32)
      'baseScore' => string 'roundUp( min( 10 , 2.514072 + 0.514634472 ) )' (length=45)
      'temporalScore' => string 'roundUp( 3.1 * 0.94 * 0.97 * 1)' (length=31)
      'envModifiedExploitabalitySubScore' => string '8.22 * 0.62 * 0.44 * 0.62 * 0.85' (length=32)
      'envImpactSubScoreMultiplier' => string 'min( 0.915, 1 - ( ( 1 - 0.22 * 0.5 ) * ( 1 - 0.22 * 0.5 ) * ( 1 - 0.22 * 1 ) ) )' (length=80)
      'envModifiedImpactSubScore' => string '6.42 * 0.382162' (length=15)
      'envScore' => string 'roundUp(min(10 , (2.45348004 + 1.181753232 ) * 0.94 * 0.97 * 1),1)' (length=66)
*/
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