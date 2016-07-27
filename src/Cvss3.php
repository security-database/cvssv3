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
 * @version 1.3.2
 * @package CVSSv3
 */

/* Start use case */
/*
$cvss = new SecurityDatabase\Cvss\Cvss3();
try {
    $cvss->register("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N");
    print_r($cvss->weight);
    print_r($cvss->scores);
    print_r($cvss->scoresLabel);
    print_r($cvss->sub_scores);
    print_r($cvss->sub_scoresLabel);
    print_r($cvss->formula);
    print_r($cvss->vector);

} catch (\Exception $e) {
    print $e->getCode()." : ".$e->getMessage();
}
*/

/* End use case */

namespace SecurityDatabase\Cvss;

class Cvss3
{
    const VERSION = '3.0';

    public $lang = "en_US";
    public $weight = array();
    public $sub_scores = array();
    public $sub_scoresLabel = array();
    public $scores = array("baseScore" => "NA",
                            "impactSubScore" => "NA",
                            "exploitabalitySubScore" => "NA",
                            "temporalScore" => "NA",
                            "envScore" => "NA",
                            "envModifiedImpactSubScore" => "NA",
                            "overallScore" => "NA"
                    );
    public $scoresLabel = array();
    public $formula = array();
    public $vector = "";

    public $vector_input_array = array();
    public $vector_inputLabel_array = array();

    private $env = array ('MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA', 'CR', 'IR', 'AR');
    private $tmp = array ('E', 'RL', 'RC');

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
            "N" => 0.85,
            "A" => 0.62,
            "L" => 0.55,
            "P" => 0.2
        ),
        "AC" => array(
            "L" => 0.77,
            "H" => 0.44
        ),
        "PR" => array(
            "N" => 0.85,
            "L" => array(
                "Default" => 0.62,
                "Scope"   => 0.68
            ),
            "H" => array(
                "Default" => 0.27,
                "Scope"   => 0.50
            )
        ),
        "UI" => array(
            "N" => 0.85,
            "R" => 0.62
        ),
        "C"  => array(
            "N" => 0,
            "L" => 0.22,
            "H" => 0.56
        ),
        "I"  => array(
            "N" => 0,
            "L" => 0.22,
            "H" => 0.56
        ),
        "A"  => array(
            "N" => 0,
            "L" => 0.22,
            "H" => 0.56
        )
    );

    private $metrics_level_optional = array(
        "E"  => array(
            "X" => 1,
            "U" => 0.91,
            "P" => 0.94,
            "F" => 0.97,
            "H" => 1
        ),
        "RL" => array(
            "X" => 1,
            "O" => 0.95,
            "T" => 0.96,
            "W" => 0.97,
            "U" => 1
        ),
        "RC" => array(
            "X" => 1,
            "U" => 0.92,
            "R" => 0.96,
            "C" => 1
        ),
        "CR" => array(
            "X" => 1,
            "L" => 0.5,
            "M" => 1,
            "H" => 1.5
        ),
        "IR" => array(
            "X" => 1,
            "L" => 0.5,
            "M" => 1,
            "H" => 1.5
        ),
        "AR" => array(
            "X" => 1,
            "L" => 0.5,
            "M" => 1,
            "H" => 1.5
        )
    );

    private $metrics_level_modified = array(
        "MAV" => array(
            "X" => 0,
            "N" => 0.85,
            "A" => 0.62,
            "L" => 0.55,
            "P" => 0.2
        ),
        "MAC" => array(
            "X" => 0,
            "L" => 0.77,
            "H" => 0.44
        ),
        "MPR" => array(
            "X" => 0,
            "N" => 0.85,
            "L" => array(
                "Default" => 0.62,
                "Scope"   => 0.68
            ),
            "H" => array(
                "Default" => 0.27,
                "Scope"   => 0.50
            )
        ),
        "MUI" => array(
            "X" => 0,
            "N" => 0.85,
            "R" => 0.62
        ),
        "MC"  => array(
            "X" => 0,
            "N" => 0,
            "L" => 0.22,
            "H" => 0.56
        ),
        "MI"  => array(
            "X" => 0,
            "N" => 0,
            "L" => 0.22,
            "H" => 0.56
        ),
        "MA"  => array(
            "X" => 0,
            "N" => 0,
            "L" => 0.22,
            "H" => 0.56
        )
    );

    /**
     * Cvss3 constructor.
     * @throws Exception
     */
    public function __construct()
    {
        if (!isset($this->lang)) {
            throw new \Exception('Not a valid language', __LINE__);
        }

        if (is_file(__dir__."/Cvss3.".$this->lang.".php") == false) {
            throw new \Exception('Traduction file does not exist', __LINE__);
        } else {
            include_once(__dir__."/Cvss3.".$this->lang.".php");
        }
    }

    /**
     * @param string $vector
     * @throws Exception
     */
    public function register($vector)
    {
        if (strlen($vector) == 0) {
            throw new \Exception("ERROR: Vector is not defined", __LINE__);
        }
        self::explodeVector($vector);
        self::checkInput();
        self::checkMandatory();
        self::checkOptional();
        self::checkModified();
        self::constructWeights();
        self::calculate();
        self::constructVector();
        self::buildLanguage();
    }

    /**
     * @param string $vector
     * @throws Exception
     */
    private function explodeVector($vector)
    {
        if (preg_match('/^CVSS:3.0.*/mi', $vector) == false) {
            throw new \Exception("ERROR: Vector is not valid", __LINE__);
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
                    throw new \Exception("ERROR: " . $metrics_mandatory . " error in value", __LINE__);
                }
            } else {
                throw new \Exception("ERROR: " . $metrics_mandatory . " not set", __LINE__);
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
                    throw new \Exception("ERROR: " . $metrics_optional . " error in value", __LINE__);
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
                    throw new \Exception("ERROR: " . $metrics_modified . " error in value", __LINE__);
                }
            }
        }
    }

    /**
     * @throws Exception
     */
    private function checkInput()
    {
        foreach ($this->vector_input_array as $key => $value) {
            if (isset($this->metrics_check_mandatory[$key])) {
                if (!preg_match("|" . $value . "|", $this->metrics_check_mandatory[$key])) {
                    throw new \Exception("ERROR: Cvss v3 vector is not compliant!", __LINE__);
                }
            } else if (isset($this->metrics_check_optional[$key])) {
                if (!preg_match("|" . $value . "|", $this->metrics_check_optional[$key])) {
                    throw new \Exception("ERROR: Cvss v3 vector is not compliant!", __LINE__);
                }
            } else if (isset($this->metrics_check_modified[$key])) {
                if (!preg_match("|" . $value . "|", $this->metrics_check_modified[$key])) {
                    throw new \Exception("ERROR: Cvss v3 vector is not compliant!", __LINE__);
                }
            } else {
                throw new \Exception("ERROR: Cvss v3 vector is not compliant!", __LINE__);
            }
        }
    }



    /**
     * @throws Exception
     *
     */
    private function constructWeights()
    {
        //Mandatory
        foreach ($this->vector_input_array as $metric => $value) {
            if ($metric == "PR") {
                if ($this->vector_input_array["S"] == "C" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_mandatory[$metric][$value])) {
                        $this->weight[$metric] = (float)$this->metrics_level_mandatory[$metric][$value]["Scope"];
                    }
                } elseif ($this->vector_input_array["S"] == "U" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_mandatory[$metric][$value])) {
                        $this->weight[$metric] = (float)$this->metrics_level_mandatory[$metric][$value]["Default"];
                    }
                } else {
                    if (isset($this->metrics_level_mandatory[$metric][$value])) {
                        $this->weight[$metric] = (float)$this->metrics_level_mandatory[$metric][$value];
                    }
                }
            } else {
                if (isset($this->metrics_level_mandatory[$metric][$value])) {
                    $this->weight[$metric] = (float)$this->metrics_level_mandatory[$metric][$value];
                }
            }
        }

        //Optional
        foreach ($this->vector_input_array as $metric => $value) {
            if (isset($this->metrics_level_optional[$metric][$value])) {
                $this->weight[$metric] = (float)$this->metrics_level_optional[$metric][$value];
            }
        }

        //Modified
        foreach ($this->vector_input_array as $metric => $value) {
            if ($metric == "MPR") {
                if ($this->vector_input_array["MS"] == "C" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_modified[$metric][$value])) {
                        $this->weight[$metric] = (float)$this->metrics_level_modified[$metric][$value]["Scope"];
                    }
                } elseif ($this->vector_input_array["MS"] == "U" && ($value == "L" || $value == "H")) {
                    if (isset($this->metrics_level_modified[$metric][$value])) {
                        $this->weight[$metric] = (float)$this->metrics_level_modified[$metric][$value]["Default"];
                    }
                } elseif ($value != 'X') {
                    if (isset($this->metrics_level_modified[$metric][$value])) {
                        $this->weight[$metric] = (float)$this->metrics_level_modified[$metric][$value];
                    }
                } else {
                    $this->weight[$metric] = (float)$this->weight[substr($metric, 1)];
                }
            } else {
                if (isset($this->metrics_level_modified[$metric][$value])) {
                    if($value != 'X') {
                        $this->weight[$metric] = (float)$this->metrics_level_modified[$metric][$value];
                    } else {
                        $this->weight[$metric] = (float)$this->weight[substr($metric, 1)];
                    }
                }
            }
        }


        foreach ($this->metrics_level_mandatory as $metric => $level) {
            if (isset($this->weight[$metric]) == false) {
                throw new \Exception("ERROR in mandatory Scores", __LINE__);
            }
        }

        foreach ($this->metrics_level_optional as $metric => $level) {
            if (isset($this->weight[$metric]) == false) {
                $this->weight[$metric] = (float)$this->metrics_level_optional[$metric]["X"];
            }
        }

        foreach ($this->metrics_level_modified as $metric => $level) {
            if (isset($this->weight[$metric]) == false) {
                $this->weight[$metric] = (float)$this->weight[substr($metric, 1)];
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

        $this->sub_scores["impactSubScoreMultiplier"] = 1 - ((1 - $this->weight["C"]) * (1 - $this->weight["I"]) * (1 - $this->weight["A"]));
        $this->formula["impactSubScoreMultiplier"] = "1 - ( ( 1 - " . $this->weight["C"] . " ) * ( 1 - " . $this->weight["I"] . " ) * ( 1 - " . $this->weight["A"] . " ) )";

        /**
         * Impact Sub Score
         */

        if ($this->vector_input_array["S"] == 'U') {
            $this->sub_scores["impactSubScore"] = 6.42 * $this->sub_scores["impactSubScoreMultiplier"];
            $this->formula["impactSubScore"] = "6.42 * " . $this->sub_scores["impactSubScoreMultiplier"];
        } elseif ($this->vector_input_array["S"] == 'C') {
            $this->sub_scores["impactSubScore"] = 7.52 * ($this->sub_scores["impactSubScoreMultiplier"] - 0.029) - 3.25 * pow(($this->sub_scores["impactSubScoreMultiplier"] - 0.02), 15);
            $this->formula["impactSubScore"] = "7.52 * ( " . $this->sub_scores["impactSubScoreMultiplier"] . " - 0.029 ) - 3.25 * pow(( " . $this->sub_scores["impactSubScoreMultiplier"] . " - 0.02 ),15)";
        } else {
            throw new \Exception("ERROR: on Scope", __LINE__);
        }

        /**
         * Exploitability Sub score
         */

        $this->sub_scores["exploitabalitySubScore"] = 8.22 * $this->weight["AV"] * $this->weight["AC"] * $this->weight["PR"] * $this->weight["UI"];
        $this->formula["exploitabalitySubScore"] = "8.22 * " . $this->weight["AV"] . " * " . $this->weight["AC"] . " * " . $this->weight["PR"] . " * " . $this->weight["UI"];

        /**
         * Base Score
         */

        if ($this->sub_scores["impactSubScore"] <= 0) {
            $this->sub_scores["baseScore"] = 0;
            $this->formula["baseScore"] = "0";
        } elseif ($this->sub_scores["impactSubScore"] > 0 && $this->vector_input_array["S"] == 'U') {
            $this->sub_scores["baseScore"] = self::roundUp(min( 10, $this->sub_scores["impactSubScore"] + $this->sub_scores["exploitabalitySubScore"]), 1);
            $this->formula["baseScore"] = "roundUp( min( 10 , " . $this->sub_scores["impactSubScore"] . " + " . $this->sub_scores["exploitabalitySubScore"] . " ) )";
        } elseif ($this->sub_scores["impactSubScore"] > 0 && $this->vector_input_array["S"] == 'C') {
            $this->sub_scores["baseScore"] = self::roundUp( min( 10, 1.08 * ($this->sub_scores["impactSubScore"] + $this->sub_scores["exploitabalitySubScore"]) ), 1 );
            $this->formula["baseScore"] = "roundUp( min( 10 , 1.08 * ( " . $this->sub_scores["impactSubScore"] . " + " . $this->sub_scores["exploitabalitySubScore"] . " ) ) )";
        } else {
            throw new \Exception("ERROR: on Base Score calcul", __LINE__);
        }

        /**
         * Temporal score
         */

        $this->sub_scores["temporalScore"] = self::roundUp($this->sub_scores["baseScore"] * $this->weight["E"] * $this->weight["RL"] * $this->weight["RC"], 1);
        $this->formula["temporalScore"] = "roundUp( " . $this->sub_scores["baseScore"] . " * " . $this->weight["E"] . " * " . $this->weight["RL"] . " * " . $this->weight["RC"] . ")";

        /**
         * Environmental score
         */


        $this->sub_scores["envImpactSubScoreMultiplier"] = min(1 - ( (1 - $this->weight["MC"] * $this->weight["CR"]) * (1 - $this->weight["MI"] * $this->weight["IR"]) * (1 - $this->weight["MA"] * $this->weight["AR"])), 0.915);
        $this->formula["envImpactSubScoreMultiplier"] = "min(1 - ( (1 - ".$this->weight["MC"]." * ".$this->weight["CR"].") * (1 - ".$this->weight["MI"]." * ".$this->weight["IR"].") * (1 - ".$this->weight["MA"]." * ".$this->weight["AR"].")), 0.915)";

        /**
         * Modified Exploitability Sub score
         */

        $this->sub_scores["envModifiedExploitabalitySubScore"] = 8.22 * $this->weight["MAV"] * $this->weight["MAC"] * $this->weight["MPR"] * $this->weight["MUI"];
        $this->formula["envModifiedExploitabalitySubScore"] = "8.22 * " . $this->weight["MAV"] . " * " . $this->weight["MAC"] . " * " . $this->weight["MPR"] . " * " . $this->weight["MUI"];

        /**
         * Modified Impact Sub score
         */

        if (isset($this->vector_input_array["MS"]) == false || ( $this->vector_input_array["MS"] == 'U' || ($this->vector_input_array["MS"] == 'X' && $this->vector_input_array["S"] == 'U')) ) {
            $this->sub_scores["envModifiedImpactSubScore"] = 6.42 * $this->sub_scores["envImpactSubScoreMultiplier"];
            $this->formula["envModifiedImpactSubScore"] = "6.42 * " . $this->sub_scores["envImpactSubScoreMultiplier"];
        } else {
            $this->sub_scores["envModifiedImpactSubScore"] = 7.52 * ($this->sub_scores["envImpactSubScoreMultiplier"] - 0.029) - 3.25 * pow(($this->sub_scores["envImpactSubScoreMultiplier"] - 0.02), 15);
            $this->formula["envModifiedImpactSubScore"] = "7.52 * ( " . $this->sub_scores["envImpactSubScoreMultiplier"] . " - 0.029 ) - 3.25 * pow(( " . $this->sub_scores["envImpactSubScoreMultiplier"] . " - 0.02 ),15)";
        }

        /**
         * Environmental Score
         */


        if (isset($this->vector_input_array["MS"]) == false || ( $this->vector_input_array["MS"] == 'U' || ($this->vector_input_array["MS"] == 'X' && $this->vector_input_array["S"] == 'U'))) {
            $this->sub_scores["envScore"] = self::roundUp(min(10, ($this->sub_scores["envModifiedImpactSubScore"] + $this->sub_scores["envModifiedExploitabalitySubScore"]) * $this->weight["E"] * $this->weight["RL"] * $this->weight["RC"]), 1);
            $this->formula["envScore"] = "roundUp(min(10 , (" . $this->sub_scores["envModifiedImpactSubScore"] . " + " . $this->sub_scores["envModifiedExploitabalitySubScore"] . " ) * " . $this->weight["E"] . " * " . $this->weight["RL"] . " * " . $this->weight["RC"] . "),1)";
        } else {
            $this->sub_scores["envScore"] = self::roundUp(min(10, 1.08 * ($this->sub_scores["envModifiedImpactSubScore"] + $this->sub_scores["envModifiedExploitabalitySubScore"]) * $this->weight["E"] * $this->weight["RL"] * $this->weight["RC"]), 1);
            $this->formula["envScore"] = "roundUp(min(10 , 1.08 * (" . $this->sub_scores["envModifiedImpactSubScore"] . " + " . $this->sub_scores["envModifiedExploitabalitySubScore"] . " ) * " . $this->weight["E"] . " * " . $this->weight["RL"] . " * " . $this->weight["RC"] . "),1)";
        }


        /**
         * Scores
         */

        $this->scores["baseScore"] = round($this->sub_scores["baseScore"],1);
        $this->scores["impactSubScore"] = round($this->sub_scores["impactSubScore"],1);
        $this->scores["exploitabalitySubScore"] = round($this->sub_scores["exploitabalitySubScore"],1);
        $this->scores["overallScore"] = round($this->sub_scores["baseScore"],1);


        foreach ($this->tmp as $k => $v) {
            $this->scores["temporalScore"] = round($this->sub_scores["temporalScore"],1);
            if (isset($this->vector_input_array[$v])) {
                $this->scores["overallScore"] = round($this->sub_scores["temporalScore"],1);
            }
        }

        foreach ($this->env as $k => $v) {
            $this->scores["envScore"] = round($this->sub_scores["envScore"],1);
            $this->scores["envModifiedImpactSubScore"] = round($this->sub_scores["envModifiedImpactSubScore"],1);
            if (isset($this->vector_input_array[$v])) {
                $this->scores["overallScore"] = round($this->sub_scores["envScore"],1);
            }
        }

    }

    /**
     * @throws Exception
     */
    private function buildLanguage() {

        foreach ( $this->scores as $key => $value) {
            if (defined("CVSSV3_" . $key)) {
                $this->scoresLabel[constant("CVSSV3_" . $key)] = $value;
            } else {
                throw new \Exception('Error in Cvss v3 vector definition', __LINE__);
            }
        }
        foreach ( $this->sub_scores as $key => $value) {
            if (defined("CVSSV3_" . $key)) {
                $this->sub_scoresLabel[constant("CVSSV3_" . $key)] = $value;
            } else {
                throw new \Exception('Error in Cvss v3 vector definition', __LINE__);
            }
        }
        foreach ( $this->vector_input_array as $key => $value) {
            if (defined("CVSSV3_" . $key."_".$value) && constant("CVSSV3_" . $key . "_" . $value)) {
                $this->vector_inputLabel_array[constant("CVSSV3_" . $key)] = constant("CVSSV3_" . $key . "_" . $value);
            } else {
                throw new \Exception('Error in Cvss v3 vector definition', __LINE__);
            }
        }
    }
    /**
     *
     */
    private function constructVector()
    {
        $this->vector = "CVSS:3.0";

        foreach ($this->vector_input_array as $vec => $input) {
            if (isset($this->metrics_check_mandatory[$vec])) {
                $this->vector .= "/" . $vec . ":" . $input;
            } else if (isset($this->metrics_check_optional[$vec]) && $input != 'X' ) {
                $this->vector .= "/" . $vec . ":" . $input;
            } else if (isset($this->metrics_check_modified[$vec]) && $input != 'X' ) {
                $this->vector .= "/" . $vec . ":" . $input;
            }
        }
    }

    /**
     * @param float $number number to round
     * @param number $precision precision for round
     * @return float
     */
    public static function roundUp($number, $precision)
    {
        $pow = pow(10, $precision);
        return (ceil($pow * $number) + ceil($pow * $number - ceil($pow * $number))) / $pow;
    }
}
