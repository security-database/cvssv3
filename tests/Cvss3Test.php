<?php

use SecurityDatabase\Cvss\Cvss3;

class Cvss3Test extends PHPUnit_Framework_TestCase {

    public function testRegister()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertTrue($cvss->vector == $vector);
        $this->assertArrayHasKey("AV", $cvss->weight);
    }

    public function testWeightArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("AV", $cvss->weight);
        $this->assertArrayHasKey("AC", $cvss->weight);
        $this->assertArrayHasKey("PR", $cvss->weight);
        $this->assertArrayHasKey("UI", $cvss->weight);
        $this->assertArrayHasKey("C", $cvss->weight);
        $this->assertArrayHasKey("I", $cvss->weight);
        $this->assertArrayHasKey("A", $cvss->weight);
        $this->assertArrayHasKey("E", $cvss->weight);
        $this->assertArrayHasKey("RL", $cvss->weight);
        $this->assertArrayHasKey("CR", $cvss->weight);
        $this->assertArrayHasKey("IR", $cvss->weight);
        $this->assertArrayHasKey("MAV", $cvss->weight);
        $this->assertArrayHasKey("MAC", $cvss->weight);
        $this->assertArrayHasKey("MPR", $cvss->weight);
        $this->assertArrayHasKey("MUI", $cvss->weight);
        $this->assertArrayHasKey("MC", $cvss->weight);
        $this->assertArrayHasKey("MI", $cvss->weight);
        $this->assertArrayHasKey("MA", $cvss->weight);
        $this->assertArrayHasKey("RC", $cvss->weight);
        $this->assertArrayHasKey("AR", $cvss->weight);
    }


    public function testScoresArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("impactSubScoreMultiplier", $cvss->scores);
        $this->assertArrayHasKey("impactSubScore", $cvss->scores);
        $this->assertArrayHasKey("exploitabalitySubScore", $cvss->scores);
        $this->assertArrayHasKey("baseScore", $cvss->scores);
        $this->assertArrayHasKey("temporalScore", $cvss->scores);
        $this->assertArrayHasKey("envModifiedExploitabalitySubScore", $cvss->scores);
        $this->assertArrayHasKey("envImpactSubScoreMultiplier", $cvss->scores);
        $this->assertArrayHasKey("envModifiedImpactSubScore", $cvss->scores);
        $this->assertArrayHasKey("envScore", $cvss->scores);
    }

    public function testFormulaArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("impactSubScoreMultiplier", $cvss->formula);
        $this->assertArrayHasKey("impactSubScore", $cvss->formula);
        $this->assertArrayHasKey("exploitabalitySubScore", $cvss->formula);
        $this->assertArrayHasKey("baseScore", $cvss->formula);
        $this->assertArrayHasKey("temporalScore", $cvss->formula);
        $this->assertArrayHasKey("envModifiedExploitabalitySubScore", $cvss->formula);
        $this->assertArrayHasKey("envImpactSubScoreMultiplier", $cvss->formula);
        $this->assertArrayHasKey("envModifiedImpactSubScore", $cvss->formula);
        $this->assertArrayHasKey("envScore", $cvss->formula);
    }

    /**
     * @expectedException Exception
     *
     */
    public function testRegisterNull()
    {
        $vector = "";
        $cvss = new Cvss3;
        $cvss->register($vector);
    }
    /**
     * @expectedException Exception
     *
     */
    public function testRegisterWithoutHead()
    {
        $vector = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

    }
}