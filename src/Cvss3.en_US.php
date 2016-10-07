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

define('CVSSV3_overallScore', 'Overall CVSS Score');

define("CVSSV3_baseMetricGroup_Legend", "This metric group represents the intrinsic and fundamental characteristics of a vulnerability that are constant over time and user environments. Determine the affected authorization scope and score Attack Vector, Attack Complexity, Privileges Required and User Interaction relative to this component.");

define("CVSSV3_AV", "Attack Vector");
define("CVSSV3_AV_N", "Network");
define("CVSSV3_AV_A", "Adjacent");
define("CVSSV3_AV_L", "Local");
define("CVSSV3_AV_P", "Physical");
define("CVSSV3_AV_Heading", "How far can the attacker be from the target system to exploit the vulnerability? The more remote an attacker, the greater the vulnerability score.");
define("CVSSV3_AV_N_Label", "A vulnerability exploitable with network access means the vulnerable authorization scope is bound to the network stack and the attacker's path to the vulnerable system is at the network layer. Such a vulnerability is often termed 'remotely exploitable'.");
define("CVSSV3_AV_A_Label", "A vulnerability exploitable with adjacent network access means the vulnerable authorization scope is bound to the network stack and the attacker's path to the vulnerable system is at the data link layer. Examples include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.");
define("CVSSV3_AV_L_Label", "A vulnerability exploitable with local access means the vulnerable authorization scope is not bound to the network stack and the attacker's path to the vulnerable authorization scope is via read / write / execute capabilities. If the attacker has the necessary Privileges Required to interact with the vulnerable authorization scope, they may be logged in locally; otherwise, they may deliver an exploit to a user and rely on User Interaction.");
define("CVSSV3_AV_P_Label", "A vulnerability exploitable with physical access requires the ability to physically touch or manipulate a vulnerable authorization scope. Physical interaction may be brief (evil maid attack) or persistent.");

define("CVSSV3_AC", "Attack Complexity");
define("CVSSV3_AC_L", "Low");
define("CVSSV3_AC_H", "High");
define("CVSSV3_AC_Heading", "Are specialized access conditions or extenuating circumstances that are beyond the attacker's control required in order to place the system in a vulnerable state?");
define("CVSSV3_AC_L_Label", "Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable exploit success against a vulnerable target.");
define("CVSSV3_AC_H_Label", "A successful attack depends on conditions outside the attacker's control. That is, a successful attack cannot be accomplished at-will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against a specific target before successful attack can be expected. A successful attack depends on attackers overcoming one OR both of the following conditions: the attacker must gather target-specific reconnaissance; or the attacker must prepare the target environment to improve exploit reliability.");

define("CVSSV3_PR", "Privileges Required");
define("CVSSV3_PR_N", "None");
define("CVSSV3_PR_L", "Low");
define("CVSSV3_PR_H", "High");
define("CVSSV3_PR_Heading", "What privileges does an attacker require before successfully exploiting the vulnerability?");
define("CVSSV3_PR_N_Label", "The attacker is unprivileged or unauthenticated.");
define("CVSSV3_PR_L_Label", "The attacker is authenticated with privileges that provide basic, low-impact capabilities. With these starting privileges an attacker is able to cause a Partial impact to one or more of: Confidentiality, Integrity, or Availability. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.");
define("CVSSV3_PR_H_Label", "The attacker is authenticated with privileges that provide significant control over component resources. With these starting privileges an attacker can cause a Complete impact to one or more of: Confidentiality, Integrity, or Availability. Alternatively, an attacker with High privileges may have the ability to cause a Partial impact to sensitive resources.");

define("CVSSV3_UI", "User Interaction");
define("CVSSV3_UI_N", "None");
define("CVSSV3_UI_R", "Required");
define("CVSSV3_UI_Heading", "What human interaction (other than the attacker's) with the vulnerable system is required in order to exploit the vulnerability?");
define("CVSSV3_UI_N_Label", "The vulnerable system can be exploited without any interaction from any user.");
define("CVSSV3_UI_R_Label", "Successful exploitation of this vulnerability requires a user to take one or more actions that may or may not be expected in a scenario involving no exploitation, or a scenario involving content provided by a seemingly trustworthy source.");

define("CVSSV3_S", "Scope");
define("CVSSV3_S_U", "Unchanged");
define("CVSSV3_S_C", "Changed");
define("CVSSV3_S_Heading", "Does a successful attack allow the attack to move from one authorization authority to another? If so, Impact (Confidentiality, Integrity and Availability) should be scored relative to the changed authorization scope.");
define("CVSSV3_S_U_Label", "The attacker attacks and impacts the environment that authorizes actions taken by the vulnerable authorization scope. Score Impact relative to the original authorization authority.");
define("CVSSV3_S_C_Label", "The attacker attacks the vulnerable authorization scope and has an impact to its environment. This causes a direct impact to another scope. Score Impact relative to the Changed Scope.");

define("CVSSV3_C", "Confidentiality Impact");
define("CVSSV3_C_H", "High");
define("CVSSV3_C_L", "Low");
define("CVSSV3_C_N", "None");
define("CVSSV3_C_Heading", "What is the impact to confidentiality of a successfully exploited vulnerability? Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones. Increased confidentiality impact increases the vulnerability score.");
define("CVSSV3_C_N_Label", "There is no impact to confidentiality within the affected scope.");
define("CVSSV3_C_L_Label", "There is informational disclosure or a bypass of access controls. Access to some restricted information is obtained, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. The information disclosure does not have a direct, serious impact on the affected scope.");
define("CVSSV3_C_H_Label", "There is total information disclosure, resulting in all resources in the affected scope being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact to the affected scope (e.g. the attacker can read the administrator's password, or private keys in memory are disclosed to the attacker).");

define("CVSSV3_I", "Integrity Impact");
define("CVSSV3_I_H", "High");
define("CVSSV3_I_L", "Low");
define("CVSSV3_I_N", "None");
define("CVSSV3_I_Heading", "What is the impact to integrity of a successfully exploited vulnerability? Integrity refers to the trustworthiness and guaranteed veracity of information. Increased integrity impact increases the vulnerability score.");
define("CVSSV3_I_N_Label", "There is no impact to integrity within the affected scope.");
define("CVSSV3_I_L_Label", "Modification of data is possible, but the attacker does not have control over the end result of a modification, or the scope of modification is constrained. The data modification does not have a direct, serious impact on the affected scope.");
define("CVSSV3_I_H_Label", "There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system.");

define("CVSSV3_A", "Availability Impact");
define("CVSSV3_A_H", "High");
define("CVSSV3_A_L", "Low");
define("CVSSV3_A_N", "None");
define("CVSSV3_A_Heading", "What is the impact to availability of a successfully exploited vulnerability? While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g. information, files) used by a affected authorization scope, this metric refers to the loss of availability of the affected authorization scope, itself, such as networked service (e.g. web, database, email, etc). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an affected authorization scope. Increased availability impact increases the vulnerability score.");
define("CVSSV3_A_N_Label", "There is no impact to availability within the affected scope.");
define("CVSSV3_A_L_Label", "There is reduced performance or interruptions in resource availability. The attacker does not have the ability to completely deny service to legitimate users, even through repeated exploitation of the vulnerability. The resources in the affected scope are either partially available all of the time, or fully available only some of the time, but the overall there is no direct, serious impact to the affected scope.");
define("CVSSV3_A_H_Label", "There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the affected scope; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious impact to the affected scope (e.g. the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).");

define("CVSSV3_temporalMetricGroup_Legend", "This metric group represents the characteristics of a vulnerability that change over time but not among user environments.");

define("CVSSV3_E", "Exploit Code Maturity");
define("CVSSV3_E_X", "Not Defined");
define("CVSSV3_E_H", "High");
define("CVSSV3_E_F", "Functional");
define("CVSSV3_E_P", "Proof-of-Concept");
define("CVSSV3_E_U", "Unproven");
define("CVSSV3_E_Heading", "What is the current state of exploit techniques or code availability?");
define("CVSSV3_E_X_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_E_U_Label", "No exploit code is available, or an exploit is entirely theoretical.");
define("CVSSV3_E_P_Label", "Proof-of-concept exploit code or an attack demonstration that is not practical for most systems is available. The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.");
define("CVSSV3_E_F_Label", "Functional exploit code is available. The code works in most situations where the vulnerability exists.");
define("CVSSV3_E_H_Label", "Either the vulnerability is exploitable by functional mobile autonomous code, or no exploit is required (manual trigger) and details are widely available. The code works in every situation, or is actively being delivered via a mobile autonomous agent (such as a worm or virus).");

define("CVSSV3_RL", "Remediation Level");
define("CVSSV3_RL_X", "Not Defined");
define("CVSSV3_RL_W", "Workaround");
define("CVSSV3_RL_T", "Temporary Fix");
define("CVSSV3_RL_O", "Official Fix");
define("CVSSV3_RL_U", "Unavailable");
define("CVSSV3_RL_Heading", "What remediations (fixes or workarounds) are currently available?");
define("CVSSV3_RL_X_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_RL_O_Label", "A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.");
define("CVSSV3_RL_T_Label", "There is an official but temporary fix available. This includes instances where the vendor issues a temporary hotfix, tool, or workaround.");
define("CVSSV3_RL_W_Label", "There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.");
define("CVSSV3_RL_U_Label", "There is either no solution available or it is impossible to apply.");

define("CVSSV3_RC", "Report Confidence");
define("CVSSV3_RC_X", "Not Defined");
define("CVSSV3_RC_C", "Confirmed");
define("CVSSV3_RC_R", "Reasonable");
define("CVSSV3_RC_U", "Unknown");
define("CVSSV3_RC_Heading", "What is the current degree of confidence in the existence of the vulnerability and the credibility of the known technical details?");
define("CVSSV3_RC_X_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_RC_U_Label", "There are reports of impacts that indicate a vulnerability is present. The reports indicate that the cause of the vulnerability is unknown, or reports may differ on the cause or impacts of the vulnerability. Reporters are uncertain of the true nature of the vulnerability, and there is little confidence in the validity of the reports or whether a static Base Score can be applied given the differences described.");
define("CVSSV3_RC_R_Label", "Significant details are published, but researchers either do not have full confidence in the root cause, or do not have access to source code to fully confirm all of the interactions that may lead to the result. Reasonable confidence exists, however, that the bug is reproducible and at least one impact is able to be verified (Proof-of-concept exploits may provide this). An example is a detailed write-up of research into a vulnerability with an explanation (possibly obfuscated or 'left as an exercise to the reader') that gives assurances on how to reproduce the results.");
define("CVSSV3_RC_C_Label", "Detailed reports exist, or functional reproduction is possible (functional exploits may provide this). Source code is available to independently verify the assertions of the research, or the author or vendor of the affected code has confirmed the presence of the vulnerability.");

define("CVSSV3_environmentalMetricGroup_Legend", "This metric group allows the Base Score metrics to be modified to reflect a particular environment. The first three metrics allow the weighting applied to the Confidentiality, Integrity and Availability chosen in the Base Score to be changed to reflect a higher or lower importance in a specific environment. The remaining metrics allow you to modify the Base Score metrics to more accurately reflect your environment.");

define("CVSSV3_CR", "Confidentiality Requirement");
define("CVSSV3_CR_X", "Not Defined");
define("CVSSV3_CR_H", "High");
define("CVSSV3_CR_M", "Medium");
define("CVSSV3_CR_L", "Low");
define("CVSSV3_CR_Heading", "How adverse an effect will a loss of confidentiality have on your organization or associated individuals? ('Medium' or 'Not Defined' will not modify the score).");
define("CVSSV3_CR_X_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_CR_L_Label", "Loss of confidentiality is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");
define("CVSSV3_CR_M_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_CR_H_Label", "Loss of confidentiality is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");

define("CVSSV3_IR", "Integrity Requirement");
define("CVSSV3_IR_X", "Not Defined");
define("CVSSV3_IR_H", "High");
define("CVSSV3_IR_M", "Medium");
define("CVSSV3_IR_L", "Low");
define("CVSSV3_IR_Heading", "How adverse an effect will a loss of integrity have on your organization or associated individuals? ('Medium' or 'Not Defined' will not modify the score).");
define("CVSSV3_IR_X_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_IR_L_Label", "Loss of integrity is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");
define("CVSSV3_IR_M_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_IR_H_Label", "Loss of integrity is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");

define("CVSSV3_AR", "Availability Requirement");
define("CVSSV3_AR_X", "Not Defined");
define("CVSSV3_AR_H", "High");
define("CVSSV3_AR_M", "Medium");
define("CVSSV3_AR_L", "Low");
define("CVSSV3_AR_Heading", "How adverse an effect will a loss of availability have on your organization or associated individuals? ('Medium' or 'Not Defined' will not modify the score).");
define("CVSSV3_AR_X_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_AR_L_Label", "Loss of availability is likely to have only a limited adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");
define("CVSSV3_AR_M_Label", "Assigning this value to the metric will not influence the score.");
define("CVSSV3_AR_H_Label", "Loss of availability is likely to have a catastrophic adverse effect on the organization or individuals associated with the organization (e.g., employees, customers).");

// All the following text should be copied exactly from the Base Score metrics (above), except that
// "Not Defined (X)" values need to be added.

define("CVSSV3_MAV", "Modified Attack Vector");
define("CVSSV3_MAV_N", "Network");
define("CVSSV3_MAV_A", "Adjacent");
define("CVSSV3_MAV_L", "Local");
define("CVSSV3_MAV_P", "Physical");
define("CVSSV3_MAV_X", "Not defined");
define("CVSSV3_MAV_Heading", "How far can the attacker be from the target system to exploit the vulnerability? The more remote an attacker, the greater the vulnerability score.");
define("CVSSV3_MAV_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MAV_N_Label", "A vulnerability exploitable with network access means the vulnerable authorization scope is bound to the network stack and the attacker's path to the vulnerable system is at the network layer. Such a vulnerability is often termed 'remotely exploitable'.");
define("CVSSV3_MAV_A_Label", "A vulnerability exploitable with adjacent network access means the vulnerable authorization scope is bound to the network stack and the attacker's path to the vulnerable system is at the data link layer. Examples include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.");
define("CVSSV3_MAV_L_Label", "A vulnerability exploitable with local access means the vulnerable authorization scope is not bound to the network stack and the attacker's path to the vulnerable authorization scope is via read / write / execute capabilities. If the attacker has the necessary Privileges Required to interact with the vulnerable authorization scope, they may be logged in locally; otherwise, they may deliver an exploit to a user and rely on User Interaction.");
define("CVSSV3_MAV_P_Label", "A vulnerability exploitable with physical access requires the ability to physically touch or manipulate a vulnerable authorization scope. Physical interaction may be brief (evil maid attack) or persistent.");

define("CVSSV3_MAC", "Modified Attack Complexity");
define("CVSSV3_MAC_L", "Low");
define("CVSSV3_MAC_H", "High");
define("CVSSV3_MAC_X", "Not defined");
define("CVSSV3_MAC_Heading", "Are specialized access conditions or extenuating circumstances that are beyond the attacker's control required in order to place the system in a vulnerable state?");
define("CVSSV3_MAC_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MAC_L_Label", "Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable exploit success against a vulnerable target.");
define("CVSSV3_MAC_H_Label", "A successful attack depends on conditions outside the attacker's control. That is, a successful attack cannot be accomplished at-will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against a specific target before successful attack can be expected. A successful attack depends on attackers overcoming one OR both of the following conditions: the attacker must gather target-specific reconnaissance; or the attacker must prepare the target environment to improve exploit reliability.");

define("CVSSV3_MPR", "Modified Privileges Required");
define("CVSSV3_MPR_N", "None");
define("CVSSV3_MPR_L", "Low");
define("CVSSV3_MPR_H", "High");
define("CVSSV3_MPR_X", "Not defined");
define("CVSSV3_MPR_Heading", "What privileges does an attacker require before successfully exploiting the vulnerability?");
define("CVSSV3_MPR_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MPR_N_Label", "The attacker is unprivileged or unauthenticated.");
define("CVSSV3_MPR_L_Label", "The attacker is authenticated with privileges that provide basic, low-impact capabilities. With these starting privileges an attacker is able to cause a Partial impact to one or more of: Confidentiality, Integrity, or Availability. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.");
define("CVSSV3_MPR_H_Label", "The attacker is authenticated with privileges that provide significant control over component resources. With these starting privileges an attacker can cause a Complete impact to one or more of: Confidentiality, Integrity, or Availability. Alternatively, an attacker with High privileges may have the ability to cause a Partial impact to sensitive resources.");

define("CVSSV3_MUI", "Modified User Interaction");
define("CVSSV3_MUI_N", "None");
define("CVSSV3_MUI_R", "Required");
define("CVSSV3_MUI_X", "Not defined");
define("CVSSV3_MUI_Heading", "What human interaction (other than the attacker's) with the vulnerable system is required in order to exploit the vulnerability?");
define("CVSSV3_MUI_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MUI_N_Label", "The vulnerable system can be exploited without any interaction from any user.");
define("CVSSV3_MUI_R_Label", "Successful exploitation of this vulnerability requires a user to take one or more actions that may or may not be expected in a scenario involving no exploitation, or a scenario involving content provided by a seemingly trustworthy source.");

define("CVSSV3_MS", "Modified Scope");
define("CVSSV3_MS_U", "Unchanged");
define("CVSSV3_MS_C", "Changed");
define("CVSSV3_MS_X", "Not defined");
define("CVSSV3_MS_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MS_Heading", "Does a successful attack allow the attack to move from one authorization authority to another? If so, Impact (Confidentiality, Integrity and Availability) should be scored relative to the changed authorization scope.");
define("CVSSV3_MS_U_Label", "The attacker attacks and impacts the environment that authorizes actions taken by the vulnerable authorization scope. Score Impact relative to the original authorization authority.");
define("CVSSV3_MS_C_Label", "The attacker attacks the vulnerable authorization scope and has an impact to its environment. This causes a direct impact to another scope. Score Impact relative to the Changed Scope.");

define("CVSSV3_MC", "Modified Confidentiality Impact");
define("CVSSV3_MC_H", "High");
define("CVSSV3_MC_L", "Low");
define("CVSSV3_MC_N", "None");
define("CVSSV3_MC_X", "Not defined");
define("CVSSV3_MC_Heading", "What is the impact to confidentiality of a successfully exploited vulnerability? Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones. Increased confidentiality impact increases the vulnerability score.");
define("CVSSV3_MC_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MC_N_Label", "There is no impact to confidentiality within the affected scope.");
define("CVSSV3_MC_L_Label", "There is informational disclosure or a bypass of access controls. Access to some restricted information is obtained, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. The information disclosure does not have a direct, serious impact on the affected scope.");
define("CVSSV3_MC_H_Label", "There is total information disclosure, resulting in all resources in the affected scope being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact to the affected scope (e.g. the attacker can read the administrator's password, or private keys in memory are disclosed to the attacker).");

define("CVSSV3_MI", "Modified Integrity Impact");
define("CVSSV3_MI_H", "High");
define("CVSSV3_MI_L", "Low");
define("CVSSV3_MI_N", "None");
define("CVSSV3_MI_X", "Not defined");
define("CVSSV3_MI_Heading", "What is the impact to integrity of a successfully exploited vulnerability? Integrity refers to the trustworthiness and guaranteed veracity of information. Increased integrity impact increases the vulnerability score.");
define("CVSSV3_MI_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MI_N_Label", "There is no impact to integrity within the affected scope.");
define("CVSSV3_MI_L_Label", "Modification of data is possible, but the attacker does not have control over the end result of a modification, or the scope of modification is constrained. The data modification does not have a direct, serious impact on the affected scope.");
define("CVSSV3_MI_H_Label", "There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system.");

define("CVSSV3_MA", "Modified Availability Impact");
define("CVSSV3_MA_H", "High");
define("CVSSV3_MA_L", "Low");
define("CVSSV3_MA_N", "None");
define("CVSSV3_MA_X", "Not defined");
define("CVSSV3_MA_Heading", "What is the impact to availability of a successfully exploited vulnerability? While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g. information, files) used by a affected authorization scope, this metric refers to the loss of availability of the affected authorization scope, itself, such as networked service (e.g. web, database, email, etc). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an affected authorization scope. Increased availability impact increases the vulnerability score.");
define("CVSSV3_MA_X_Label", "Use the value assigned to the corresponding Base Score metric.");
define("CVSSV3_MA_N_Label", "There is no impact to availability within the affected scope.");
define("CVSSV3_MA_L_Label", "There is reduced performance or interruptions in resource availability. The attacker does not have the ability to completely deny service to legitimate users, even through repeated exploitation of the vulnerability. The resources in the affected scope are either partially available all of the time, or fully available only some of the time, but the overall there is no direct, serious impact to the affected scope.");
define("CVSSV3_MA_H_Label", "There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the affected scope; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious impact to the affected scope (e.g. the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).");
