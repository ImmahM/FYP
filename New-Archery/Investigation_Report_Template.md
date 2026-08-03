# Investigation Report

## ArcherySec: Modernized Vulnerability Management Platform

**Student Name:** [Your Name]
**Student ID:** [Your ID]
**Programme:** [Your Programme]
**University:** Asia Pacific University of Technology and Innovation

---

## Table of Contents

- [Chapter 1: Introduction](#chapter-1-introduction)
- [Chapter 2: Literature Review](#chapter-2-literature-review)
- [Chapter 3: Methodology](#chapter-3-methodology)
- [Chapter 4: Findings and Analysis](#chapter-4-findings-and-analysis)
- [Chapter 5: Conclusion and Recommendations](#chapter-5-conclusion-and-recommendations)

---

## Chapter 1: Introduction

### 1.1 Introduction

The increased reliance on digital systems has increased organizational attack space and this puts critical infrastructures at risk of high level cybersecurity attacks. The constantly growing complexity of applications, networks, and cloud-based environments has created a need to have integrated, automated and continuous security assessment practices. The contemporary cybersecurity frameworks are now concerned with the DevSecOps culture and approach that embeds security throughout the software development lifecycle through automating, and constant monitoring (OWASP, 2023). The methodology addresses the weaknesses of traditional security models which are often premised on the late-stage vulnerability disclosures, and are not tied to the development and deployment pipelines.

ArcherySec has become one of the most popular open-source solutions that have been created with a specific purpose in organizing and synchronizing application and network security results in the present-day DevSecOps setting. ArcherySec is not a traditional standalone scanner like others but an Application Security Orchestration and Correlation (ASOC) platform that integrates the findings of over 80 integrated scanning tools, such as OWASP ZAP, Burp Suite, OpenVAS, Nmap, Nikto, SSLScan, and SAST/DAST utilities, into a single unified vulnerability database (Swarup, 2025; ArcherySec Documentation, 2026).

ArcherySec addresses the critical industry issue of tool separation in which each scanner presents results in different formats, slowing triage and analysis by normalizing different scan results, removing duplicates, and mapping results into a centralized risk dashboard. Moreover, ArcherySec is directly integrated with CI/CD pipelines through its official CLI and allows executing scans automatically, real-time gating of insecure builds, and integrating hassle-free into DevOps processes (ArcherySec Documentation, 2026).

Nonetheless, current implementations of ArcherySec have some restrictions that should be overcome to be able to live up to the expectations of an enterprise. These constraints are uneven deployment procedures, a deficit in supporting hardened containerization, unfinished RBAC enforcement, and lack of automated scheduling of periodic scans, and reporting (ArcherySec GitHub, 2026). Also, though ArcherySec has good scanner integration, the default evidence retention processes cannot support the needs of an organization that needs standard audit logs.

Recent DevSecOps studies emphasize the significance of infrastructure-as-code, role-based access control, and automated scheduling, adequate reporting, and effective scanning results as the key elements of the current security pipelines gaps that should be filled with this modernization project (Abdiukov, 2024; OWASP, 2023).

According to recent findings on the DevSecOps research, there is a rise in the demand of AI-based analytical support in vulnerability management systems due to the increasing number and complexity of security findings by automated scanners. Although conventional tools are useful in identifying vulnerabilities, security teams frequently have problems with alert fatigue and unequal prioritization when analysis is based on only static severity indicators. In turn, AI in the sphere is an increasingly popular decision-support system, which assists analysts prioritizing vulnerabilities and improving the clarity of reporting, and not a replacement of the familiar security scanners or human analysts (Abdiukov, 2024; Fu et al., 2024).

In this case, the given project discusses the use of explainable and AI-based, rule-based techniques to enhance vulnerability analysis without compromising transparency, governance, and adherence to the DevSecOps practices and the Sustainable Development Goal 9, which is concerned with resilient and innovative digital infrastructure.

This modernization is in accordance with UN Sustainable Development Goal 9 (Industry, Innovation, and Infrastructure) as it improves the building blocks of safe digital infrastructure. Without good cybersecurity, SDG 9 is aimed at developing a resilient system and promoting innovation. This project is directly connected with sustainable innovation of technology by enhancement of an open-source security platform and responsible and secure innovation.

### 1.2 Problem Statement

The complexity of the modern digital infrastructures has brought more security risks as organizations are currently relying on distributed applications, containerized workloads and continuous delivery pipelines. Such architectural changes have offered new entry points to be exploited and exposure of networks and applications has significantly risen. DevSecOps guidelines stipulate that continuous security testing is a must, and in most instances, organizations still sporadically employ numerous unrelated scanners, which fail to display well-structured, non-redundant, or inconsistent data (OWASP, 2023). This fragmentation provides operational gaps with vulnerabilities which are either not detected, not prioritized or not dealt with.

Despite the reality that ArcherySec is an open-source Application Security Orchestration and Correlation (ASOC) layer, the original platform has some limitations that hinder its functionality in the face of modern and scaled DevSecOps environment. The current ArcherySec architecture comprises a number of open-source scanners, and ingestion and correlation can be inconsistent due to the variety of formats and evidence formats produced by tools such as OWASP ZAP, Nmap, Nikto, OpenVAS, and Dependency-Check (Swarup, 2025; ArcherySec Documentation, 2026). The outcome is a repetition of the results, partial risk classification, and ineffective triage process.

Additionally, an automated security testing study shows that the existing pipelines have completely automated, containerized, reproducible environments of dynamic and static analysis tools conditions, which the original ArcherySec deployment does not satisfy completely (Abdiukov, 2024). The lack of hardened Docker-based deployments causes organizations to have inconsistent scanner behavior, unpredictable runtime failures, and challenges with integrating ArcherySec into CI/CD workflows. Combined with the absence of automated planning of repeat scans, these issues slow down development teams, and introduce security gaps.

The other critical issue is lack of governance. The initial ArcherySec lacks much Role-Based Access Control (RBAC) to the extent that it is unable to implement the principles of the least-privilege. Its existing security system requires an efficient IAM to prevent inappropriate running of scans, data export and editing that play a vital role in mitigating insider threats (Marquis, 2024). In this kind of state of affairs as a bad access governance, there is a scenario whereby no one is liable to privileged procedures and delicate vulnerable outcomes might undergo to unqualified or unauthorized individuals.

Also evidence management and reporting is also limited. The former is not complex and lacks enterprise level PDF reports, executive summary, CVSS enhanced prioritization improvement and structured archiving of scanner artifact. This makes it more difficult to store compliance documentation in organizations, to track trends in the past or to provide audit requirements.

All these restrictions together dis-aggregated scanner data, absence of hardened deployment, inadequate automation, poor RBAC, and poor reporting all have a tremendous impact on the operation of the platform. They also hinder its alignment to SDG 9 (Industry, Innovation, and Infrastructure) that is concerned with resilient technological systems and unsafe innovation practices. The main secret of making ArcherySec a scalable, enterprise-ready, automation-first vulnerability management solution is to close these gaps by modernizing them.

### 1.2.1 Rationale

ArcherySec must be modernized to be more responsive to the requirements of the new DevSecOps environment where it must be automated, scalable, and integrated to meet the requirements of the fast delivery of software and a robust digital infrastructure. Although ArcherySec already integrates the performance of over 80 scanners and demonstrates one vulnerability presentation, the constraints it possesses currently are an ad-hoc deployment, lack of access control, lack of automation, and lack of scan results; reduce it to less of a worthy security coordination tool in business settings (Swarup, 2025; ArcherySec Documentation, 2026).

The literature on DevSecOps practices is centered around the notion that organizations need to have stable, containerized, and reproducible scanning environments and a continuous evaluation process to avoid security blind spots and to reduce the detection times (OWASP, 2023; Abdiukov, 2024). Moreover, the security governance literature points out that a strong Role-Based Access Control (RBAC) is essential in reducing insider risks and applying the least-privilege principles, which is not fully in place in the original ArcherySec (Marquis, 2024).

The upgrades of ArcherySec, such as upgrading its RBAC model, deploying hardened Docker-based deployment, increasing automation, and enhancing orchestration logic, thus, directly cover these gaps, facilitating more reliable correlation, reproducible scanning, and secure control of operations.

UN SDG 9 (Industry, Innovation, and Infrastructure) is not needed due to technical reasons, but a modernization that will assist in making infrastructure more resilient to digital threats, sustainable innovation by using open source tooling, and secure-by-design development models to safeguard critical infrastructure. This way, improving ArcherySec is not merely a technical requirement, but also a strategic step towards ensuring secure, modern, and sustainable cybersecurity ecosystems.

### 1.3 Project Aim

To design and develop a better and innovated version of the ArcherySec vulnerability management system, which will increase the reliability of security scanning processes and access governance and automated DevSecOps processes, a more resistant and sustainable digital infrastructure in line with SDG 9.

### 1.4 Objectives

1. To study the limitations of the existing ArcherySec platform and identify key areas requiring modernization for improved security and scalability.
2. To design a reproducible, containerized deployment architecture using Docker and Docker Compose to enhance reliability and CI/CD compatibility.
3. To develop advanced scanner orchestration features, including automated scheduling, background task execution, and configurable scan parameters.
4. To enhance management of vulnerabilities in terms of normalized scanner analysis, CVSS-based risk score, structured reporting, and role-based access control.
5. To evaluate the functionality, performance, and effectiveness of the modernized ArcherySec system in supporting DevSecOps workflows and SDG 9 goals.

### 1.5 Scope

#### 1.5.1 Target Users

The ultimate target users in this project comprise the students, lecturers, and technical testing personnel in the university setting who will be the main users of the enhanced ArcherySec platform. These groups are also directly used in cybersecurity related learning, education, or system assessment, and are therefore available to be tested, provided feedback, and collect data during the research.

The platform is used by students who can be beginners and more advanced cybersecurity students to perform vulnerability scans, analyze findings, and has hands-on experience with multi-scanner orchestration and DevSecOps processes. The system is utilized by lecturers as administrators and facilitators to show safe development, classroom activities, and make sure that the potentials of the platform are matched to the learning outcomes of cybersecurity and DevSecOps modules.

Other supporting activities include the technical testing personnel like the lab technicians or IT support staff who will deploy, configure and maintain the platform within the lab setting of the universities. They make sure that the Docker-Based deployment is working well, scanners are running, and RBAC, scheduling, and logging functions are being enforced.

The system will enable lecturers to:
1. Demonstrate vulnerability scanning and DevSecOps workflows clearly during labs and lectures.
2. Guide students in understanding scanner outputs, reporting formats, and security orchestration.
3. Provide technical support and clarification when misunderstandings or configuration issues occur.

The system will enable students to:
1. Use a simplified but powerful interface suitable for mixed skill levels.
2. Perform web, network, and dependency scans using multiple integrated tools.
3. Interpret normalized, CVSS-enriched results and analyze generated PDF reports.
4. Gain hands-on experience with automated scheduling, orchestration, and DevSecOps practices.

The system will enable technical testing staff to:
1. Deploy and maintain the platform using standardized Docker-based configurations.
2. Ensure scanners operate reliably and consistently across lab sessions.
3. Monitor system performance, access control, audit logs, and scheduled tasks.
4. Support lecturers and students in resolving operational or configuration issues.

#### 1.5.2 Nature of Challenges

There are a number of challenges associated with modernizing ArcherySec to be used in a university environment, as the level of technical competence and responsibility between the students, lecturers, and the technical testing employees is different. Learners vary in their level of experience with cybersecurity, with some being total beginners, and others being highly trained and skilled in cybersecurity. It is, therefore, important that the platform is both accessible and powerful.

Lecturers also have the challenge of creating practical lab activities and demonstrations that are based on the dependability of scanner execution, dependability of vulnerability reports and dependability of orchestration features. The platform can be too complex or inconsistent, which can interrupt teaching, hinder hands-on learning, or complicate the acquisition of fundamental DevSecOps and vulnerability assessment concepts by students.

Meanwhile, technical test staff will be forced to ensure that the system can successfully be put into practice and supported in typical lab environments. It involves troubleshooting Docker-based deployments, scanning tools of raw wound sockets, network configurations, RBAC-based implementation, scheduled tasks and audit logs; all with university hardware, shared networks, and restricted access to administrative privileges.

### 1.6 Inclusion Criteria

The inclusion criteria determine the limits of this study by detailing the participants, tools, and concepts that will be regarded as relevant to the study. These criteria will guarantee that the investigation will be focused on the vulnerability management practices in accordance with the goals of the suggested ArcherySec platform. This investigation includes:

1. There are those who have simple to the moderate understanding of cybersecurity concepts, such as students and young professionals in the field of cybersecurity.
2. Tools that are typically applied in practice like OWASP ZAP, Nikto, Nmap, Nessus, and other software-based security scanners.
3. Concepts related to vulnerability scanning, vulnerability management, and multi-scanner orchestration.
4. Security processes that cover the identification of vulnerabilities, analysis, prioritization, and reporting.
5. Vulnerability assessment activities that are performed using software and are in an academic, training, or general organizational setting.

### 1.7 Exclusion Criteria

The exclusion criteria specify the areas which are deliberately avoided in this investigation to manage the scope of the project and avoid the unwanted complexity in the investigation phase. This investigation excludes:

1. Highly developed exploit development and offensive penetration testing.
2. Live exploitation or testing of production systems.
3. Detailed system implementation, performance benchmarking or tool-level optimization.
4. Hardware-based security testing and Internet of Things (IoT) security assessments.
5. Cybersecurity policy enforcement and compliance analysis, legal, regulatory, or organizational.

### 1.8 Potential Benefits

#### 1.8.1 Tangible Benefits

1. The improved platform enhances accuracy and reliability of vulnerability tests through unified and multi-orchestration by the multiple called the multiplier scanner.
2. Containerized deployment offers predictable and stable operation in university labs.
3. Normalized results, CVSS scoring and exportable reports are excellent, professional outputs that can be easily utilized in academics.
4. Improved RBAC improves security control as only authorized members are allowed to perform sensitive activities.
5. The scan history and dashboards will provide a higher visibility of the trend and high-risk findings.

#### 1.8.2 Intangible Benefits

1. Learners have a hands-on cybersecurity experience with actual vulnerability management tools.
2. An easier interface will make students more engaged and confident, particularly beginners.
3. The teaching environment is more efficient with good demonstrations and laboratories, which are of advantage to lecturers.
4. Logging and governance capabilities enable technical staff to have better control and oversight.
5. The SDG 9 that the project is supporting is the creation of safe, innovative, and resilient digital infrastructure in academia.

### 1.9 Overview of IR

* Chapter 1 will consist of the introduction, background of the project, rationale, aim, objectives, scope, target users, challenges and the anticipated benefits.
* Chapter 2 includes a literature review, including the DevSecOps concept, vulnerability management tools, RBAC models, orchestration of scanners, and a comparison to similar platforms that are applicable to ArcherySec.
* Chapter 3 describes the methodology employed in the project, such as the approach to the research, the methods to be used to collect data, the groups of participants and the methods of evaluation.
* Chapter 4 wraps up the report with a conclusion on findings, project limitations and proposals on how the project can be improved.

---

## Chapter 2: Literature Review

### 2.1 Introduction to DevSecOps

[Write content about DevSecOps concepts, principles, and how it integrates security into the software development lifecycle. Reference OWASP, NIST, and industry best practices.]

### 2.2 Vulnerability Management Landscape

[Write content about current vulnerability management practices, tools, and challenges in modern cybersecurity.]

### 2.3 Application Security Orchestration and Correlation (ASOC)

[Write content about ASOC platforms, their role in DevSecOps, and how they address tool fragmentation.]

### 2.4 Role-Based Access Control (RBAC) Models

[Write content about RBAC principles, importance in security platforms, and implementation patterns.]

### 2.5 Containerization and Deployment

[Write content about Docker, containerized deployments, benefits for reproducibility and CI/CD integration.]

### 2.6 AI-Based Vulnerability Analysis

[Write content about AI/ML applications in vulnerability prioritization, risk scoring, and decision support.]

### 2.7 Sustainable Development Goal 9

[Write content about SDG 9, its relevance to cybersecurity infrastructure, and how this project contributes.]

### 2.8 Comparative Analysis

[Write content comparing ArcherySec with similar platforms like DefectDojo, SonarQube, etc.]

### 2.9 Summary

[Summarize key findings from the literature review.]

---

## Chapter 3: Methodology

### 3.1 Research Approach

[Describe the research approach - qualitative, quantitative, or mixed methods.]

### 3.2 System Development Methodology

[Describe the software development methodology - Agile, Waterfall, DevOps, etc.]

### 3.3 Data Collection Methods

[Describe how data will be collected - surveys, interviews, system testing, etc.]

### 3.4 Participants

[Describe the target participants - students, lecturers, technical staff.]

### 3.5 Evaluation Methods

[Describe how the system will be evaluated - UAT, performance testing, etc.]

### 3.6 Tools and Technologies

[List the tools and technologies used in the project.]

### 3.7 Ethical Considerations

[Describe ethical considerations and approvals.]

---

## Chapter 4: Findings and Analysis

### 4.1 System Implementation

[Describe the implemented system architecture and features.]

### 4.2 Scanner Integration Results

[Present results from scanner integrations - ZAP, Nikto, Nmap, OpenVAS.]

### 4.3 RBAC Implementation

[Present the RBAC implementation results and evaluation.]

### 4.4 Automated Scheduling

[Present the automated scheduling system results.]

### 4.5 Report Generation

[Present the PDF report generation results and sample reports.]

### 4.6 Vulnerability Prioritization

[Present the AI-based risk scoring and prioritization results.]

### 4.7 User Acceptance Testing

[Present UAT results from testers.]

### 4.8 Discussion

[Discuss findings in relation to objectives and literature.]

---

## Chapter 5: Conclusion and Recommendations

### 5.1 Summary of Findings

[Summarize the key findings from the project.]

### 5.2 Achievement of Objectives

[Discuss how each objective was achieved.]

### 5.3 Limitations

[Discuss the limitations of the project.]

### 5.4 Recommendations for Future Work

[Provide recommendations for future improvements.]

### 5.5 Conclusion

[Provide a concluding statement on the project's contribution.]

---

## References

[List all references in APA or Harvard format.]

---

## Appendices

### Appendix A: System Architecture Diagram

[Insert architecture diagram.]

### Appendix B: Sample Scan Results

[Insert sample scan results.]

### Appendix C: Sample PDF Reports

[Insert sample generated reports.]

### Appendix D: UAT Evaluation Forms

[Insert completed UAT forms.]

### Appendix E: Survey Questionnaires

[Insert survey instruments.]
