<?php

use SecurityDatabase\Cvss\Cvss3;

class Cvss3Test extends PHPUnit_Framework_TestCase {

    public function testRegister()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertTrue($cvss->vector == $vector);
        $this->assertArrayHasKey("AV", $cvss->scores);
    }

    public function testScoresArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("AV", $cvss->scores);
        $this->assertArrayHasKey("AC", $cvss->scores);
        $this->assertArrayHasKey("PR", $cvss->scores);
        $this->assertArrayHasKey("UI", $cvss->scores);
        $this->assertArrayHasKey("C", $cvss->scores);
        $this->assertArrayHasKey("I", $cvss->scores);
        $this->assertArrayHasKey("A", $cvss->scores);
        $this->assertArrayHasKey("E", $cvss->scores);
        $this->assertArrayHasKey("RL", $cvss->scores);
        $this->assertArrayHasKey("CR", $cvss->scores);
        $this->assertArrayHasKey("IR", $cvss->scores);
        $this->assertArrayHasKey("MAV", $cvss->scores);
        $this->assertArrayHasKey("MAC", $cvss->scores);
        $this->assertArrayHasKey("MPR", $cvss->scores);
        $this->assertArrayHasKey("MUI", $cvss->scores);
        $this->assertArrayHasKey("MC", $cvss->scores);
        $this->assertArrayHasKey("MI", $cvss->scores);
        $this->assertArrayHasKey("MA", $cvss->scores);
        $this->assertArrayHasKey("RC", $cvss->scores);
        $this->assertArrayHasKey("AR", $cvss->scores);
    }
    

    public function testCalculArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("ISCbase", $cvss->calcul);
        $this->assertArrayHasKey("ISC", $cvss->calcul);
        $this->assertArrayHasKey("ESC", $cvss->calcul);
        $this->assertArrayHasKey("BS", $cvss->calcul);
        $this->assertArrayHasKey("TS", $cvss->calcul);
        $this->assertArrayHasKey("MESC", $cvss->calcul);
        $this->assertArrayHasKey("ISCmodified", $cvss->calcul);
        $this->assertArrayHasKey("MISS", $cvss->calcul);
        $this->assertArrayHasKey("ES", $cvss->calcul);
    }

    public function testFormulaArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("ISCbase", $cvss->formula);
        $this->assertArrayHasKey("ISC", $cvss->formula);
        $this->assertArrayHasKey("ESC", $cvss->formula);
        $this->assertArrayHasKey("BS", $cvss->formula);
        $this->assertArrayHasKey("TS", $cvss->formula);
        $this->assertArrayHasKey("MESC", $cvss->formula);
        $this->assertArrayHasKey("ISCmodified", $cvss->formula);
        $this->assertArrayHasKey("MISS", $cvss->formula);
        $this->assertArrayHasKey("ES", $cvss->formula);
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