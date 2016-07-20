<?php
/**
 *  Common Vulnerability Scoring System Version 3.0 Calculator
 *
 *  Copyright [2015] [Security-Database]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @desc Class to get and calculate CVSS v3 scores
 * @author Security-Database <info@security-database.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0  Apache License 2.0
 * @version 1.3.0
 * @package CVSSv3
 */

/* Start use case */
/*
$cvss = new SecurityDatabase\Cvss\Cvss3();
try {
    $cvss->register("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N");
    print_r($cvss->scores);
    print_r($cvss->calcul);
    print_r($cvss->formula);
    print_r($cvss->vector);

} catch (Exception $e) {
    print $e->getCode()." : ".$e->getMessage();
}
*/

/* End use case */

namespace SecurityDatabase\Cvss;

use Exception;

class Cvss3
{
    const VERSION = '3.0';

    public $scores = array();
    public $calcul = array();
    public $formula = array();
    public $vector = "";

    private $vector_input_array = array();

    private $metrics_check_mandatory = array(
        "AV" => "[N,A,L,P]",
        "AC" => "[L,H]",
        "PR" => "[N,L,H]",
        "UI" => "[N,R]",
        "S"  => "[U,C]",
        "C"  => "[N,L,H]",
        "I"  => "[N,L,H]",
        "A"  => "[N,L,H]"
    );

    private $metrics_check_optional = array(
        "E"  => "[X,U,P,F,H]",
        "RL" => "[X,O,T,W,U]",
        "RC" => "[X,U,R,C]",
        "CR" => "[X,L,M,H]",
        "IR" => "[X,L,M,H]",
        "AR" => "[X,L,M,H]"
    );

    private $metrics_check_modified = array(
        "MAV" => "[X,N,A,L,P]",
        "MAC" => "[X,L,H]",
        "MPR" => "[X,N,L,H]",
        "MUI" => "[X,N,R]",
        "MS"  => "[X,U,C]",
        "MC"  => "[X,N,L,H]",
        "MI"  => "[X,N,L,H]",
        "MA"  => "[X,N,L,H]"
    );

    private $metrics_level_mandatory = array(
        "AV" => array(
            "N" => '0.85',
            "A" => '0.62',
            "L" => '0.55',
            "P" => '0.2'
        ),
        "AC" => array(
            "L" => '0.77',
            "H" => '0.44'
        ),
        "PR" => array(
            "N" => '0.85',
            "L" => array(
                "Default" => '0.62',
                "Scope"   => '0.68'
            ),
            "H" => array(
                "Default" => '0.27',
                "Scope"   => '0.50'
            )
        ),
        "UI" => array(
            "N" => '0.85',
            "R" => '0.62'
        ),
        "C"  => array(
            "N" => '0',
            "L" => '0.22',
            "H" => '0.56'
        ),
        "I"  => array(
            "N" => '0',
            "L" => '0.22',
            "H" => '0.56'
        ),
        "A"  => array(
            "N" => '0',
            "L" => '0.22',
            "H" => '0.56'
        )
    );

    private $metrics_level_optional = array(
        "E"  => array(
            "X" => '1',
            "U" => '0.91',
            "P" => '0.94',
            "F" => '0.97',
            "H" => '1'
        ),
        "RL" => array(
            "X" => '1',
            "O" => '0.95',
            "T" => '0.96',
            "W" => '0.97',
            "U" => '1'
        ),
        "RC" => array(
            "X" => '1',
            "U" => '0.92',
            "R" => '0.96',
            "C" => '1'
        ),
        "CR" => array(
            "X" => '1',
            "L" => '0.5',
            "M" => '1',
            "H" => '1.5'
        ),
        "IR" => array(
            "X" => '1',
            "L" => '0.5',
            "M" => '1',
            "H" => '1.5'
        ),
        "AR" => array(
            "X" => '1',
            "L" => '0.5',
            "M" => '1',
            "H" => '1.5'
        )
    );

    private $metrics_level_modified = array(
        "MAV" => array(
            "X" => '0',
            "N" => '0.85',
            "A" => '0.62',
            "L" => '0.55',
            "P" => '0.2'
        ),
        "MAC" => array(
            "X" => '0',
            "L" => '0.77',
            "H" => '0.44'
        ),
        "MPR" => array(
            "X" => '0',
            "N" => '0.85',
            "L" => array(
                "Default" => '0.62',
                "Scope"   => '0.68'
            ),
            "H" => array(
                "Default" => '0.27',
                "Scope"   => '0.50'
            )
        ),
        "MUI" => array(
            "X" => '0',
            "N" => '0.85',
            "R" => '0.62'
        ),
        "MC"  => array(
            "X" => '0',
            "N" => '0',
            "L" => '0.22',
            "H" => '0.56'
        ),
        "MI"  => array(
            "X" => '0',
            "N" => '0',
            "L" => '0.22',
            "H" => '0.56'
        ),
        "MA"  => array(
            "X" => '0',
            "N" => '0',
            "L" => '0.22',
            "H" => '0.56'
        )
    );

    /**
     * @param string $vector
     * @throws Exception
     */
    public function register($vector)
    {
        if (strlen($vector) == 0) {
            throw new Exception("ERROR: Vector is not defined");
        }
        self::explodeVector($vector);
        self::checkMandatory();
        self::checkOptional();
        self::checkModified();
        self::constructScores();
        self::calculate();
        self::constructVector();
    }

    /**
     * @param string $vector
     * @throws Exception
     */
    private function explodeVector($vector)
    {
        if (preg_match('/^CVSS:3.0.*/mi', $vector) == false) {
            throw new Exception("ERROR: Vector is not valid");
        }
        $vector = str_replace("CVSS:3.0/", "", $vector);
        $vector_input_array_temp = explode('/', $vector);

        foreach ($vector_input_array_temp as $k => $v) {
            $temp = explode(":", $v);
            $this->vector_input_array[$temp[0]] = $temp[1];
        }
    }


    /**
     * @throws Exception
     */
    private function checkMandatory()
    {
        foreach ($this->metrics_check_mandatory as $metrics_mandatory => $value_mandatory) {
            if (isset($this->vector_input_array[$metrics_mandatory])) {
                if (!preg_match("|" . $value_mandatory . "|", $this->vector_input_array[$metrics_mandatory])) {
                    throw new Exception("ERROR: " . $metrics_mandatory . " error in value", __LINE__);
                }
            } else {
                throw new Exception("ERROR: " . $metrics_mandatory . " not set", __LINE__);
            }
        }
    }

    /**
     * @throws Exception
     */
    private function checkOptional()
    {
        foreach ($this->metrics_check_optional as $metrics_optional => $value_optional) {
            if (isset($this->vector_input_array[$metrics_optional])) {
                if (!preg_match("|" . $value_optional . "|", $this->vector_input_array[$metrics_optional])) {
                    throw new Exception("ERROR: " . $metrics_optional . " error in value", __LINE__);
                }
            }
        }
    }

    /**
     * @throws Exception
     */
    private function checkModified()
    {
        foreach ($this->metrics_check_modified as $metrics_modified => $value_modified) {
            if (isset($this->vector_input_array[$value_modified])) {
                if (!preg_match("|" . $value_modified . "|", $this->vector_input_array[$value_modified])) {
                    throw new Exception("ERROR: " . $metrics_modified . " error in value", __LINE__);
                }
            }
        }
    }

    /**
     * @throws Exception
     *
     */
    private function constructScores()
    {
        //Mandatory
        foreach ($this->vector_input_array as $metric => $value) {
            if ($metric == "PR") {
                if ($this->vector_input_array["S"] == "C" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_mandatory[$metric][$value])) {
                        $this->scores[$metric] = $this->metrics_level_mandatory[$metric][$value]["Scope"];
                    }
                } elseif ($this->vector_input_array["S"] == "U" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_mandatory[$metric][$value])) {
                        $this->scores[$metric] = $this->metrics_level_mandatory[$metric][$value]["Default"];
                    }
                } else {
                    if (isset($this->metrics_level_mandatory[$metric][$value])) {
                        $this->scores[$metric] = $this->metrics_level_mandatory[$metric][$value];
                    }
                }
            } else {
                if (isset($this->metrics_level_mandatory[$metric][$value])) {
                    $this->scores[$metric] = $this->metrics_level_mandatory[$metric][$value];
                }
            }
        }

        //Optional
        foreach ($this->vector_input_array as $metric => $value) {
            if (isset($this->metrics_level_optional[$metric][$value])) {
                $this->scores[$metric] = $this->metrics_level_optional[$metric][$value];
            }
        }

        //Modified
        foreach ($this->vector_input_array as $metric => $value) {
            if ($metric == "MPR") {
                if ($this->vector_input_array["MS"] == "C" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_modified[$metric][$value])) {
                        $this->scores[$metric] = $this->metrics_level_modified[$metric][$value]["Scope"];
                    }
                } elseif ($this->vector_input_array["MS"] == "U" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_modified[$metric][$value])) {
                        $this->scores[$metric] = $this->metrics_level_modified[$metric][$value]["Default"];
                    }
                } else {
                    if (isset($this->metrics_level_modified[$metric][$value])) {
                        $this->scores[$metric] = $this->metrics_level_modified[$metric][$value];
                    }
                }
            } else {
                if (isset($this->metrics_level_modified[$metric][$value])) {
                    $this->scores[$metric] = $this->metrics_level_modified[$metric][$value];
                }
            }
        }


        foreach ($this->metrics_level_mandatory as $metric => $level) {
            if (isset($this->scores[$metric]) == false) {
                throw new Exception("ERROR in mandatory Scores", __LINE__);
            }
        }

        foreach ($this->metrics_level_optional as $metric => $level) {
            if (isset($this->scores[$metric]) == false) {
                $this->scores[$metric] = $this->metrics_level_optional[$metric]["X"];
            }
        }

        foreach ($this->metrics_level_modified as $metric => $level) {
            if (isset($this->scores[$metric]) == false) {
                $this->scores[$metric] = $this->scores[substr($metric, 1)];
            }
        }
    }

    /**
     * @throws Exception
     */
    private function calculate()
    {

        /**
         * ISC : Impact Sub score
         * ESC : Exploitability Sub score
         */

        /**
         * Impact Sub base score
         */

        $this->calcul["ISCbase"] = 1 - ((1 - $this->scores["C"]) * (1 - $this->scores["I"]) * (1 - $this->scores["A"]));
        $this->formula["ISCbase"] = "1 - ( ( 1 - " . $this->scores["C"] . " ) * ( 1 - " . $this->scores["I"] . " ) * ( 1 - " . $this->scores["A"] . " ) )";

        /**
         * Impact Sub Score
         */

        if ($this->vector_input_array["S"] == 'U') {
            $this->calcul["ISC"] = 6.42 * $this->calcul["ISCbase"];
            $this->formula["ISC"] = "6.42 * " . $this->calcul["ISCbase"];
        } elseif ($this->vector_input_array["S"] == 'C') {
            $this->calcul["ISC"] = 7.52 * ($this->calcul["ISCbase"] - 0.029) - 3.25 * pow(($this->calcul["ISCbase"] - 0.02), 15);
            $this->formula["ISC"] = "7.52 * ( " . $this->calcul["ISCbase"] . " - 0.029 ) - 3.25 * pow(( " . $this->calcul["ISCbase"] . " - 0.02 ),15)";
        } else {
            throw new Exception("ERROR: on Scope", __LINE__);
        }

        /**
         * Exploitability Sub score
         */

        $this->calcul["ESC"] = 8.22 * $this->scores["AV"] * $this->scores["AC"] * $this->scores["PR"] * $this->scores["UI"];
        $this->formula["ESC"] = "8.22 * " . $this->scores["AV"] . " * " . $this->scores["AC"] . " * " . $this->scores["PR"] . " * " . $this->scores["UI"];

        /**
         * Base Score
         */

        if ($this->calcul["ISC"] <= 0) {
            $this->calcul["BS"] = 0;
            $this->formula["BS"] = "0";
        } elseif ($this->calcul["ISC"] > 0 && $this->vector_input_array["S"] == 'U') {
            $this->calcul["BS"] = self::roundUp(
                min(
                    10,
                    $this->calcul["ISC"] + $this->calcul["ESC"]
                ),
                1
            );
            $this->formula["BS"] = "roundUp( min( 10 , " . $this->calcul["ISC"] . " + " . $this->calcul["ESC"] . " ) )";
        } elseif ($this->calcul["ISC"] > 0 && $this->vector_input_array["S"] == 'C') {
            $this->calcul["BS"] = self::roundUp( min( 10, 1.08 * ($this->calcul["ISC"] + $this->calcul["ESC"]) ), 1 );
            $this->formula["BS"] = "roundUp( min( 10 , 1.08 * ( " . $this->calcul["ISC"] . " + " . $this->calcul["ESC"] . " ) ) )";
        } else {
            throw new Exception("ERROR: on Base Score calcul", __LINE__);
        }

        /**
         * Temporal score
         */

        $this->calcul["TS"] = self::roundUp($this->calcul["BS"] * $this->scores["E"] * $this->scores["RL"] * $this->scores["RC"], 1);
        $this->formula["TS"] = "roundUp( " . $this->calcul["BS"] . " * " . $this->scores["E"] . " * " . $this->scores["RL"] . " * " . $this->scores["RC"] . ")";

        /**
         * Environmental score
         */

        /**
         * Modified Exploitability Sub score
         */

        $this->calcul["MESC"] = 8.22 * $this->scores["MAV"] * $this->scores["MAC"] * $this->scores["MPR"] * $this->scores["MUI"];
        $this->formula["MESC"] = "8.22 * " . $this->scores["MAV"] . " * " . $this->scores["MAC"] . " * " . $this->scores["MPR"] . " * " . $this->scores["MUI"];

        /**
         * Modified Impact Sub score
         */

        $this->calcul["ISCmodified"] = min(0.915, 1 - ((1 - $this->scores["MC"] * $this->scores["CR"]) * (1 - $this->scores["MI"] * $this->scores["IR"]) * (1 - $this->scores["MA"] * $this->scores["AR"])));
        $this->formula["ISCmodified"] = "min( 0.915, 1 - ( ( 1 - " . $this->scores["MC"] . " * " . $this->scores["CR"] . " ) * ( 1 - " . $this->scores["MI"] . " * " . $this->scores["IR"] . " ) * ( 1 - " . $this->scores["MA"] . " * " . $this->scores["AR"] . " ) ) )";

        if (isset($this->vector_input_array["MS"]) == true && ( $this->vector_input_array["MS"] == 'U' || ($this->vector_input_array["MS"] == 'X' && $this->vector_input_array["S"] == 'U')) ) {
            $this->calcul["MISS"] = 6.42 * $this->calcul["ISCmodified"];
            $this->formula["MISS"] = "6.42 * " . $this->calcul["ISCmodified"];
        } else {
            $this->calcul["MISS"] = 7.52 * ($this->calcul["ISCmodified"] - 0.029) - 3.25 * pow(($this->calcul["ISCmodified"] - 0.02), 15);
            $this->formula["MISS"] = "7.52 * ( " . $this->calcul["ISCmodified"] . " - 0.029 ) - 3.25 * pow(( " . $this->calcul["ISCmodified"] . " - 0.02 ),15)";
        }

        /**
         * Environmental Score
         */

        if (isset($this->vector_input_array["MS"]) == true && ( $this->vector_input_array["MS"] == 'U' || ($this->vector_input_array["MS"] == 'X' && $this->vector_input_array["S"] == 'U'))) {
            $this->calcul["ES"] = self::roundUp(min(10, ($this->calcul["MISS"] + $this->calcul["MESC"]) * $this->scores["E"] * $this->scores["RL"] * $this->scores["RC"]), 1);
            $this->formula["ES"] = "roundUp(min(10 , (" . $this->calcul["MISS"] . " + " . $this->calcul["MESC"] . " ) * " . $this->scores["E"] . " * " . $this->scores["RL"] . " * " . $this->scores["RC"] . "),1)";
        } else {
            $this->calcul["ES"] = self::roundUp(min(10, 1.08 * ($this->calcul["MISS"] + $this->calcul["MESC"]) * $this->scores["E"] * $this->scores["RL"] * $this->scores["RC"]), 1);
            $this->formula["ES"] = "roundUp(min(10 , 1.08 * (" . $this->calcul["MISS"] . " + " . $this->calcul["MESC"] . " ) * " . $this->scores["E"] . " * " . $this->scores["RL"] . " * " . $this->scores["RC"] . "),1)";
        }
    }

    /**
     *
     */
    private function constructVector()
    {
        $this->vector = "CVSS:3.0";
        foreach ($this->vector_input_array as $vec => $input) {
            $this->vector .= "/" . $vec . ":" . $input;
        }
    }

    /**
     * @param float $number number to round
     * @param number $precision precision for round
     * @return float
     */
    public function roundUp($number, $precision)
    {
        $pow = pow(10, $precision);
        return (ceil($pow * $number) + ceil($pow * $number - ceil($pow * $number))) / $pow;
    }
}
