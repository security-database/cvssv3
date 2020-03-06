<?php

define("CVSSV3_ND", "Not defined");
define('CVSSV3_MORE', 'Read more ...');

define("CVSSV3_baseScore", "Base Score");
define("CVSSV3_temporalScore", "Temporal Score");
define("CVSSV3_envScore", "Environmental Score");
define("CVSSV3_envModifiedImpactSubScore", "Environmental Modified Impact SubScore");
define("CVSSV3_envImpactSubScoreMultiplier", "Environmental Impact SubScore Multiplier");
define("CVSSV3_envModifiedExploitabalitySubScore", "Environmental Modified Exploitabality SubScore");
define("CVSSV3_exploitabalitySubScore", "Exploitabality Sub Score");
define("CVSSV3_impactSubScore", "impact SubScore");
define("CVSSV3_impactSubScoreMultiplier", "Impact SubScore Multiplier");

define("CVSSV3_baseRating", "Base Rating");
define("CVSSV3_tempRating", "Temporal Rating");
define("CVSSV3_envRating", "Environmental Rating");

define('CVSSV3_overallScore', 'Overall CVSS Score');

define("CVSSV3_baseMetricGroup_Legend", "The Base Metric group represents the intrinsic  characteristics of a vulnerability that are constant over time and across user environments. Determine the vulnerable component and score Attack Vector, Attack Complexity, Privileges Required and User Interaction relative to this.");

define("CVSSV3_AV", "Attack Vector");
define("CVSSV3_AV_N", "Network");
define("CVSSV3_AV_A", "Adjacent");
define("CVSSV3_AV_L", "Local");
define("CVSSV3_AV_P", "Physical");
define("CVSSV3_AV_Heading", "This metric reflects the context by which vulnerability exploitation is possible. The Base Score increases the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component.");
define("CVSSV3_AV_N_Label", "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed, up to and including the entire Internet. Such a vulnerability is often termed 'remotely exploitable' and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers)..");
define("CVSSV3_AV_A_Label", "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone).");
define("CVSSV3_AV_L_Label", "The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., tricking a legitimate user into opening a malicious document).");
define("CVSSV3_AV_P_Label", "The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent.");

define("CVSSV3_AC", "Attack Complexity");
define("CVSSV3_AC_L", "Low");
define("CVSSV3_AC_H", "High");
define("CVSSV3_AC_Heading", "This metric describes the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability. Such conditions may require the collection of more information about the target or computational exceptions. The assessment of this metric excludes any requirements for user interaction in order to exploit the vulnerability. If a specific configuration is required for an attack to succeed, the Base metrics should be scored assuming the vulnerable component is in that configuration.");
define("CVSSV3_AC_L_Label", "Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component.");
define("CVSSV3_AC_H_Label", "A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may require an attacker to: gather knowledge about the environment in which the vulnerable target/component exists; prepare the target environment to improve exploit reliability; or inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack).");

define("CVSSV3_PR", "Privileges Required");
define("CVSSV3_PR_N", "None");
define("CVSSV3_PR_L", "Low");
define("CVSSV3_PR_H", "High");
define("CVSSV3_PR_Heading", "This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.");
define("CVSSV3_PR_N_Label", "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.");
define("CVSSV3_PR_L_Label", "The attacker is authorized with (i.e., requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.");
define("CVSSV3_PR_H_Label", "The attacker is authorized with (i.e., requires) privileges that provide significant (e.g., administrative) control over the vulnerable component that could affect component-wide settings and files.");

define("CVSSV3_UI", "User Interaction");
define("CVSSV3_UI_N", "None");
define("CVSSV3_UI_R", "Required");
define("CVSSV3_UI_Heading", "This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner.");
define("CVSSV3_UI_N_Label", "The vulnerable system can be exploited without any interaction from any user.");
define("CVSSV3_UI_R_Label", "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.");

define("CVSSV3_S", "Scope");
define("CVSSV3_S_U", "Unchanged");
define("CVSSV3_S_C", "Changed");
define("CVSSV3_S_Heading", "Does a successful attack impact a component other than the vulnerable component? If so, the Base Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.");
define("CVSSV3_S_U_Label", "An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.");
define("CVSSV3_S_C_Label", "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.");

define("CVSSV3_C", "Confidentiality Impact");
define("CVSSV3_C_H", "High");
define("CVSSV3_C_L", "Low");
define("CVSSV3_C_N", "None");
define("CVSSV3_C_Heading", "This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.");
define("CVSSV3_C_N_Label", "There is no loss of confidentiality within the impacted component.");
define("CVSSV3_C_L_Label", "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.");
define("CVSSV3_C_H_Label", "There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.");

define("CVSSV3_I", "Integrity Impact");
define("CVSSV3_I_H", "High");
define("CVSSV3_I_L", "Low");
define("CVSSV3_I_N", "None");
define("CVSSV3_I_Heading", "This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.");
define("CVSSV3_I_N_Label", "There is no loss of integrity within the impacted component.");
define("CVSSV3_I_L_Label", "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.");
define("CVSSV3_I_H_Label", "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.");

define("CVSSV3_A", "Availability Impact");
define("CVSSV3_A_H", "High");
define("CVSSV3_A_L", "Low");
define("CVSSV3_A_N", "None");
define("CVSSV3_A_Heading", "This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component.");
define("CVSSV3_A_N_Label", "There is no impact to availability within the impacted component.");
define("CVSSV3_A_L_Label", "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.");
define("CVSSV3_A_H_Label", "There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).");

define("CVSSV3_temporalMetricGroup_Legend", "The Temporal metrics measure the current state of exploit techniques or code availability, the existence of any patches or workarounds, or the confidence that one has in the description of a vulnerability.");

define("CVSSV3_E", "Exploit Code Maturity");
define("CVSSV3_E_X", "Not Defined");
define("CVSSV3_E_H", "High");
define("CVSSV3_E_F", "Functional");
define("CVSSV3_E_P", "Proof-of-Concept");
define("CVSSV3_E_U", "Unproven");
define("CVSSV3_E_Heading", "This metric measures the likelihood of the vulnerability being attacked, and is typically based on the current state of exploit techniques, exploit code availability, or active, 'in-the-wild' exploitation.");
define("CVSSV3_E_X_Label", "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning High.");
define("CVSSV3_E_U_Label", "No exploit code is available, or an exploit is theoretical.");
define("CVSSV3_E_P_Label", "Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.");
define("CVSSV3_E_F_Label", "Functional exploit code is available. The code works in most situations where the vulnerability exists.");
define("CVSSV3_E_H_Label", "Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely-available, easy-to-use automated tools.");

define("CVSSV3_RL", "Remediation Level");
define("CVSSV3_RL_X", "Not Defined");
define("CVSSV3_RL_W", "Workaround");
define("CVSSV3_RL_T", "Temporary Fix");
define("CVSSV3_RL_O", "Official Fix");
define("CVSSV3_RL_U", "Unavailable");
define("CVSSV3_RL_Heading", "The Remediation Level of a vulnerability is an important factor for prioritization. The typical vulnerability is unpatched when initially published. Workarounds or hotfixes may offer interim remediation until an official patch or upgrade is issued. Each of these respective stages adjusts the temporal score downwards, reflecting the decreasing urgency as remediation becomes final.");
define("CVSSV3_RL_X_Label", "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning Unavailable.");
define("CVSSV3_RL_O_Label", "A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.");
define("CVSSV3_RL_T_Label", "There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.");
define("CVSSV3_RL_W_Label", "There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.");
define("CVSSV3_RL_U_Label", "There is either no solution available or it is impossible to apply..");

define("CVSSV3_RC", "Report Confidence");
define("CVSSV3_RC_X", "Not Defined");
define("CVSSV3_RC_C", "Confirmed");
define("CVSSV3_RC_R", "Reasonable");
define("CVSSV3_RC_U", "Unknown");
define("CVSSV3_RC_Heading", "This metric measures the degree of confidence in the existence of the vulnerability and the credibility of the known technical details. Sometimes only the existence of vulnerabilities are publicized, but without specific details. For example, an impact may be recognized as undesirable, but the root cause may not be known. The vulnerability may later be corroborated by research which suggests where the vulnerability may lie, though the research may not be certain. Finally, a vulnerability may be confirmed through acknowledgement by the author or vendor of the affected technology. The urgency of a vulnerability is higher when a vulnerability is known to exist with certainty. This metric also suggests the level of technical knowledge available to would-be attackers.");
define("CVSSV3_RC_X_Label", "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Temporal Score, i.e., it has the same effect on scoring as assigning Confirmed.");
define("CVSSV3_RC_U_Label", "There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base score can be applied given the differences described. An example is a bug report which notes that an intermittent but non-reproducible crash occurs, with evidence of memory corruption suggesting that denial of service, or possible more serious impacts, may result.");
define("CVSSV3_RC_R_Label", "Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (Proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or 'left as an exercise to the reader') that gives assurances on how to reproduce the results.");
define("CVSSV3_RC_C_Label", "Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability.");

define("CVSSV3_environmentalMetricGroup_Legend", "These metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user’s organization, measured in terms of complementary/alternative security controls in place, Confidentiality, Integrity, and Availability. The metrics are the modified equivalent of base metrics and are assigned metric values based on the component placement in organization infrastructure.");

define("CVSSV3_CR", "Confidentiality Requirement");
define("CVSSV3_CR_X", "Not Defined");
define("CVSSV3_CR_H", "High");
define("CVSSV3_CR_M", "Medium");
define("CVSSV3_CR_L", "Low");
define("CVSSV3_CR_Heading", "These metrics enable the analyst to customize the CVSS score depending on the importance of the Confidentiality of the affected IT asset to a user’s organization, relative to other impacts. This metric modifies the environmental score by reweighting the Modified Confidentiality impact metric versus the other modified impacts.");
define("CVSSV3_CR_X_Label", "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.");
define("CVSSV3_CR_L_Label", "Loss of Confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");
define("CVSSV3_CR_M_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_CR_H_Label", "Loss of Confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");

define("CVSSV3_IR", "Integrity Requirement");
define("CVSSV3_IR_X", "Not Defined");
define("CVSSV3_IR_H", "High");
define("CVSSV3_IR_M", "Medium");
define("CVSSV3_IR_L", "Low");
define("CVSSV3_IR_Heading", "These metrics enable the analyst to customize the CVSS score depending on the importance of the Integrity of the affected IT asset to a user’s organization, relative to other impacts. This metric modifies the environmental score by reweighting the Modified Integrity impact metric versus the other modified impacts.");
define("CVSSV3_IR_X_Label", "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.");
define("CVSSV3_IR_L_Label", "Loss of Integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");
define("CVSSV3_IR_M_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_IR_H_Label", "Loss of Integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");

define("CVSSV3_AR", "Availability Requirement");
define("CVSSV3_AR_X", "Not Defined");
define("CVSSV3_AR_H", "High");
define("CVSSV3_AR_M", "Medium");
define("CVSSV3_AR_L", "Low");
define("CVSSV3_AR_Heading", "These metrics enable the analyst to customize the CVSS score depending on the importance of the Availability of the affected IT asset to a user’s organization, relative to other impacts. This metric modifies the environmental score by reweighting the Modified Availability impact metric versus the other modified impacts.");
define("CVSSV3_AR_X_Label", "Assigning this value indicates there is insufficient information to choose one of the other values, and has no impact on the overall Environmental Score, i.e., it has the same effect on scoring as assigning Medium.");
define("CVSSV3_AR_L_Label", "Loss of Availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");
define("CVSSV3_AR_M_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_AR_H_Label", "Loss of Availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");

// All the following text should be copied exactly from the Base Score metrics (above), except that
// "Not Defined (X)" values need to be added.

define("CVSSV3_MAV", "Modified Attack Vector");
define("CVSSV3_MAV_N", "Network");
define("CVSSV3_MAV_A", "Adjacent");
define("CVSSV3_MAV_L", "Local");
define("CVSSV3_MAV_P", "Physical");
define("CVSSV3_MAV_X", "Not defined");
define("CVSSV3_MAV_Heading", "This metric reflects the context by which vulnerability exploitation is possible. The Environmental Score increases the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component.");
define("CVSSV3_MAV_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MAV_N_Label", "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed, up to and including the entire Internet. Such a vulnerability is often termed 'remotely exploitable' and can be thought of as an attack being exploitable at the protocol level one or more network hops away.");
define("CVSSV3_MAV_A_Label", "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN).");
define("CVSSV3_MAV_L_Label", "The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., tricking a legitimate user into opening a malicious document).");
define("CVSSV3_MAV_P_Label", "The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent.");

define("CVSSV3_MAC", "Modified Attack Complexity");
define("CVSSV3_MAC_L", "Low");
define("CVSSV3_MAC_H", "High");
define("CVSSV3_MAC_X", "Not defined");
define("CVSSV3_MAC_Heading", "This metric describes the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability. Such conditions may require the collection of more information about the target or computational exceptions. The assessment of this metric excludes any requirements for user interaction in order to exploit the vulnerability. If a specific configuration is required for an attack to succeed, the Base metrics should be scored assuming the vulnerable component is in that configuration.");
define("CVSSV3_MAC_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MAC_L_Label", "Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component.");
define("CVSSV3_MAC_H_Label", "A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may require an attacker to: gather knowledge about the environment in which the vulnerable target/component exists; prepare the target environment to improve exploit reliability; or inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack).");

define("CVSSV3_MPR", "Modified Privileges Required");
define("CVSSV3_MPR_N", "None");
define("CVSSV3_MPR_L", "Low");
define("CVSSV3_MPR_H", "High");
define("CVSSV3_MPR_X", "Not defined");
define("CVSSV3_MPR_Heading", "This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.");
define("CVSSV3_MPR_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MPR_N_Label", "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.");
define("CVSSV3_MPR_L_Label", "The attacker is authorized with (i.e., requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.");
define("CVSSV3_MPR_H_Label", "The attacker is authorized with (i.e., requires) privileges that provide significant (e.g., administrative) control over the vulnerable component that could affect component-wide settings and files.");

define("CVSSV3_MUI", "Modified User Interaction");
define("CVSSV3_MUI_N", "None");
define("CVSSV3_MUI_R", "Required");
define("CVSSV3_MUI_X", "Not defined");
define("CVSSV3_MUI_Heading", "This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner.");
define("CVSSV3_MUI_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MUI_N_Label", "The vulnerable system can be exploited without any interaction from any user.");
define("CVSSV3_MUI_R_Label", "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.");

define("CVSSV3_MS", "Modified Scope");
define("CVSSV3_MS_U", "Unchanged");
define("CVSSV3_MS_C", "Changed");
define("CVSSV3_MS_X", "Not defined");
define("CVSSV3_MS_Heading", "Does a successful attack impact a component other than the vulnerable component? If so, the Base Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.");
define("CVSSV3_MS_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MS_U_Label", "An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.");
define("CVSSV3_MS_C_Label", "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.");

define("CVSSV3_MC", "Modified Confidentiality Impact");
define("CVSSV3_MC_H", "High");
define("CVSSV3_MC_L", "Low");
define("CVSSV3_MC_N", "None");
define("CVSSV3_MC_X", "Not defined");
define("CVSSV3_MC_Heading", "This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.");
define("CVSSV3_MC_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MC_N_Label", "There is no loss of confidentiality within the impacted component.");
define("CVSSV3_MC_L_Label", "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.");
define("CVSSV3_MC_H_Label", "There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.");

define("CVSSV3_MI", "Modified Integrity Impact");
define("CVSSV3_MI_H", "High");
define("CVSSV3_MI_L", "Low");
define("CVSSV3_MI_N", "None");
define("CVSSV3_MI_X", "Not defined");
define("CVSSV3_MI_Heading", "This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.");
define("CVSSV3_MI_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MI_N_Label", "There is no loss of integrity within the impacted component.");
define("CVSSV3_MI_L_Label", "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.");
define("CVSSV3_MI_H_Label", "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.");

define("CVSSV3_MA", "Modified Availability Impact");
define("CVSSV3_MA_H", "High");
define("CVSSV3_MA_L", "Low");
define("CVSSV3_MA_N", "None");
define("CVSSV3_MA_X", "Not defined");
define("CVSSV3_MA_Heading", "This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component.");
define("CVSSV3_MA_X_Label", "The value assigned to the corresponding Base metric is used.");
define("CVSSV3_MA_N_Label", "There is no impact to availability within the impacted component.");
define("CVSSV3_MA_L_Label", "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.");
define("CVSSV3_MA_H_Label", "There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).");


define('CVSSV3_RATING_N', 'NA');
define('CVSSV3_RATING_L', 'Low');
define('CVSSV3_RATING_M', 'Medium');
define('CVSSV3_RATING_H', 'High');
define('CVSSV3_RATING_C', 'Critical');