<?php

use SecurityDatabase\Cvss\Cvss3;

class Cvss3Test extends PHPUnit_Framework_TestCase {

    public function testRegister()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertTrue($cvss->getVector() == $vector);
        $this->assertArrayHasKey("AV", $cvss->getWeight());
    }

    public function testWeightArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("AV", $cvss->getWeight());
        $this->assertArrayHasKey("AC", $cvss->getWeight());
        $this->assertArrayHasKey("PR", $cvss->getWeight());
        $this->assertArrayHasKey("UI", $cvss->getWeight());
        $this->assertArrayHasKey("C", $cvss->getWeight());
        $this->assertArrayHasKey("I", $cvss->getWeight());
        $this->assertArrayHasKey("A", $cvss->getWeight());
        $this->assertArrayHasKey("E", $cvss->getWeight());
        $this->assertArrayHasKey("RL", $cvss->getWeight());
        $this->assertArrayHasKey("CR", $cvss->getWeight());
        $this->assertArrayHasKey("IR", $cvss->getWeight());
        $this->assertArrayHasKey("MAV", $cvss->getWeight());
        $this->assertArrayHasKey("MAC", $cvss->getWeight());
        $this->assertArrayHasKey("MPR", $cvss->getWeight());
        $this->assertArrayHasKey("MUI", $cvss->getWeight());
        $this->assertArrayHasKey("MC", $cvss->getWeight());
        $this->assertArrayHasKey("MI", $cvss->getWeight());
        $this->assertArrayHasKey("MA", $cvss->getWeight());
        $this->assertArrayHasKey("RC", $cvss->getWeight());
        $this->assertArrayHasKey("AR", $cvss->getWeight());
    }

    public function testSubScoresArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("impactSubScoreMultiplier", $cvss->getSubScores());
        $this->assertArrayHasKey("impactSubScore", $cvss->getSubScores());
        $this->assertArrayHasKey("exploitabalitySubScore", $cvss->getSubScores());
        $this->assertArrayHasKey("baseScore", $cvss->getSubScores());
        $this->assertArrayHasKey("temporalScore", $cvss->getSubScores());
        $this->assertArrayHasKey("envModifiedExploitabalitySubScore", $cvss->getSubScores());
        $this->assertArrayHasKey("envImpactSubScoreMultiplier", $cvss->getSubScores());
        $this->assertArrayHasKey("envModifiedImpactSubScore", $cvss->getSubScores());
        $this->assertArrayHasKey("envScore", $cvss->getSubScores());
    }
    public function testScoresArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("baseScore", $cvss->getScores());
        $this->assertArrayHasKey("impactSubScore", $cvss->getScores());
        $this->assertArrayHasKey("exploitabalitySubScore", $cvss->getScores());
        $this->assertArrayHasKey("temporalScore", $cvss->getScores());
        $this->assertArrayHasKey("envScore", $cvss->getScores());
        $this->assertArrayHasKey("envModifiedImpactSubScore", $cvss->getScores());
        $this->assertArrayHasKey("overallScore", $cvss->getScores());
    }
    public function testFormulaArray()
    {
        $vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N";
        $cvss = new Cvss3;
        $cvss->register($vector);

        $this->assertArrayHasKey("impactSubScoreMultiplier", $cvss->getFormula());
        $this->assertArrayHasKey("impactSubScore", $cvss->getFormula());
        $this->assertArrayHasKey("exploitabalitySubScore", $cvss->getFormula());
        $this->assertArrayHasKey("baseScore", $cvss->getFormula());
        $this->assertArrayHasKey("temporalScore", $cvss->getFormula());
        $this->assertArrayHasKey("envModifiedExploitabalitySubScore", $cvss->getFormula());
        $this->assertArrayHasKey("envImpactSubScoreMultiplier", $cvss->getFormula());
        $this->assertArrayHasKey("envModifiedImpactSubScore", $cvss->getFormula());
        $this->assertArrayHasKey("envScore", $cvss->getFormula());
    }


    public function testVector1()
    {
        $vector = "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/MAC:H/MPR:H/MUI:R/MC:L/MI:N";
        $cvss = new Cvss3;
        $cvss->register($vector);
        $this->assertTrue( 9.0 === (float)$cvss->getScores()["baseScore"]);
        $this->assertTrue( 9.0 === (float)$cvss->getScores()["temporalScore"]);
        $this->assertTrue( 5.9 === (float)$cvss->getScores()["envScore"]);

    }

    public function testVector2()
    {
        $vector = "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/RL:O/RC:C/IR:M/AR:H/MAC:H/MPR:H/MUI:R/MC:L/MI:N";
        $cvss = new Cvss3;
        $cvss->register($vector);
        $this->assertTrue( 8.4 === (float)$cvss->getScores()["baseScore"]);
        $this->assertTrue( 8.0 === (float)$cvss->getScores()["temporalScore"]);
        $this->assertTrue( 7.0 === (float)$cvss->getScores()["envScore"]);

    }

    public function testVector3()
    {
        $vector = "CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/RL:O/RC:C/IR:M/AR:H/MAV:L/MPR:H/MUI:R/MS:U/MC:L/MI:N";
        $cvss = new Cvss3;
        $cvss->register($vector);
        $this->assertTrue( 8.4 === (float)$cvss->getScores()["baseScore"]);
        $this->assertTrue( 8.0 === (float)$cvss->getScores()["temporalScore"]);
        $this->assertTrue( 6.0 === (float)$cvss->getScores()["envScore"]);

    }

    public function testVector4()
    {
        $vector = "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H/E:P/RL:O/RC:C/IR:M/AR:H/MAV:L/MPR:H/MUI:R/MS:C/MC:L/MI:N";
        $cvss = new Cvss3;
        $cvss->register($vector);
        $this->assertTrue( 8.0 === (float)$cvss->getScores()["baseScore"]);
        $this->assertTrue( 7.2 === (float)$cvss->getScores()["temporalScore"]);
        $this->assertTrue( 7.0 === (float)$cvss->getScores()["envScore"]);

    }

    public function testVector5()
    {
        $vector = "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H/E:P/RL:O/RC:U/IR:M/AR:H/MAV:L/MUI:R/MS:C/MC:L/MI:N";
        $cvss = new Cvss3;
        $cvss->register($vector);
        $this->assertTrue( 8.0 === (float)$cvss->getScores()["baseScore"]);
        $this->assertTrue( 6.6 === (float)$cvss->getScores()["temporalScore"]);
        $this->assertTrue( 7.1 === (float)$cvss->getScores()["envScore"]);

    }

    /**
     * @expectedException Exception
     *
     */
    public function testRegisterNull()
    {
        $cvss = new Cvss3;
        $cvss->register('');
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

    /**
     * @expectedException Exception
     */
    public function testLangNull()
    {
        $cvss = new Cvss3;
        $this->assertTrue($cvss->setLocale('') == true);
    }

    public function testLang()
    {
        $cvss = new Cvss3;
        $this->assertTrue($cvss->setLocale('en_US') == true);
    }
}
