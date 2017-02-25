##PHP Class for CVSS v3 Calculator

[![Build Status](https://travis-ci.org/security-database/cvssv3.svg?branch=master)](https://travis-ci.org/security-database/cvssv3)

[![Latest Stable Version](https://poser.pugx.org/security-database/cvss/version)](https://packagist.org/packages/security-database/cvss)
[![Total Downloads](https://poser.pugx.org/security-database/cvss/downloads)](https://packagist.org/packages/security-database/cvss)
[![Latest Unstable Version](https://poser.pugx.org/security-database/cvss/v/unstable)](//packagist.org/packages/security-database/cvss)
[![License](https://poser.pugx.org/security-database/cvss/license)](https://packagist.org/packages/security-database/cvss)

###Version


####2.0.3
- EnvScore calcultation fix with MPR and Scope when MS is not set (again)
- Cleaner code push by @faynwol
- Add some UnitTest on vectors vs CVSSv3 website

####2.0.2
- EnvScore calcultation fix with MPR and Scope when MS is not set
- EnvScore Formula, with now 2 RoundUp instead of One
- Add some UnitTest on vectors vs CVSSv3 website

####2.0.1
- EnvScore calcultation fix when envModifiedImpactSubScore <= 0
- EnvScore Formula set to 0 in that case
- Change some props to static
- Change Clean method to handle static properties

####2.0
- Change public vars to private vars
- Add getter to all private vars
- Add setter to locale vars
- Add locale validator in __constructor and setter
- Change phpUnit test case to reflect getter and setter
- Update documentation
- Update some DocBlock
- Update to 2.0 since getters and setters are not backward compatible

- Todo more and more phpUnit test case ...

####1.3.2
- Modify DocBlock with \Exception
- Add a Clean() function to be able to clean Object before register another one
- Add public vector_part (Base, Temp and Env vector part)
- Modify private to public base, env and tmp
- Change private to public some vars ($this->base, $this->env, $this->tmp)
- Fix \Exception()
- Add Code on some Exception (__construct && register && explodeVector)
- Change constructVector() to construct only mandatory vector (optional and modified are not put on vector if value is 'X' == No set)
- Fix check constant on language
- Fix modified metrics defaulting
- Add a constructor that load language files
- Add a reverse vector checker

####1.3.1
- Fix envImpactSubScoreMultiplier
- Add Scores priority

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
use SecurityDatabase\Cvss\Cvss3;

try {
	$cvss = new Cvss3();
	$cvss->register("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N/E:P/RL:W/CR:L/IR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L");
	
    print_r($cvss->getWeight());
    print_r($cvss->getScores());
    print_r($cvss->getScoresLabel());
    print_r($cvss->getSubScores());
    print_r($cvss->getSubScoresLabel());
    print_r($cvss->getFormula());
    print_r($cvss->getVector());
    (...)

} catch (Exception $e) {
	print $e->getCode()." : ".$e->getMessage();
}
```

####Usage
You can now get some informations :

Get weight of every piece of the vector (array());
```php
print_r($cvss->getWeight());
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

Get scores used in scores (array());
```php
print_r($cvss->getScores());
/*
array (size=7)
  'baseScore' => float 6.7
  'impactSubScore' => float 5.7576309677951
  'exploitabalitySubScore' => float 0.3924228
  'temporalScore' => string 'NA' (length=2)
  'envScore' => string 'NA' (length=2)
  'envModifiedImpactSubScore' => string 'NA' (length=2)
  'overallScore' => float 6.7
*/
```

Get scores with label (en_US) used in scoresLabel (array());
```php
print_r($cvss->getScoresLabel());
/*
array (size=7)
  'Base Score' => float 6.7
  'impact SubScore' => float 5.7576309677951
  'Exploitabality Sub Score' => float 0.3924228
  'Temporal Score' => string 'NA' (length=2)
  'Environmental Score' => string 'NA' (length=2)
  'Environmental Modified Impact SubScore' => string 'NA' (length=2)
  'Overall CVSS Score' => float 6.7
*/
```

Get sub scores used in sub_scores (array());
```php
print_r($cvss->getScores());
/*
array (size=9)
  'impactSubScoreMultiplier' => float 0.8064
  'impactSubScore' => float 5.7576309677951
  'exploitabalitySubScore' => float 0.3924228
  'baseScore' => float 6.7
  'temporalScore' => float 6.7
  'envModifiedExploitabalitySubScore' => float 0.3924228
  'envImpactSubScoreMultiplier' => float 0.8064
  'envModifiedImpactSubScore' => float 5.7576309677951
  'envScore' => float 6.7
*/
```

Get sub scores with label (en_US) used in sub_scoresLabel (array());
```php
print_r($cvss->getScoresLabel());
/*
array (size=9)
  'Impact SubScore Multiplier' => float 0.8064
  'impact SubScore' => float 5.7576309677951
  'Exploitabality Sub Score' => float 0.3924228
  'Base Score' => float 6.7
  'Temporal Score' => float 6.7
  'Environmental Modified Exploitabality SubScore' => float 0.3924228
  'Environmental Impact SubScore Multiplier' => float 0.8064
  'Environmental Modified Impact SubScore' => float 5.7576309677951
  'Environmental Score' => float 6.7
*/
```


Get Formula with detail
```php
print_r($cvss->getFormula());

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
print $cvss->getVector();

/* return a string :
   CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N/E:P/RL:W/CR:L/IR:L/MAV:A/MAC:H/MPR:L/MUI:N/MS:U/MC:L/MI:L/MA:L
*/
```

####Contribute
If you found any error on the class, please, fork it, push a PR or contact us at "info at security-database.com"
