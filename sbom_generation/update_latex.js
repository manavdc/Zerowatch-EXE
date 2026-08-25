/**
 * update_latex.js
 *
 * Processes scan-output.json and dynamically updates LaTeX report chapter templates.
 */

const fs = require("fs");
const path = require("path");

// Helper to escape LaTeX special characters to prevent compilation failures
const escapeLatex = (str) => {
  if (!str) return "";
  return String(str)
    .replace(/\\/g, "\\textbackslash{}")
    .replace(/([&%$#_{}])/g, "\\$1")
    .replace(/~/g, "\\textasciitilde{}")
    .replace(/\^/g, "\\textasciicircum{}");
};

function run() {
  const jsonPath = path.join(__dirname, "..", "scan-output.json");
  if (!fs.existsSync(jsonPath)) {
    console.error(`❌ Error: scan-output.json not found at ${jsonPath}`);
    process.exit(1);
  }

  console.log("📖 Reading scan output JSON...");
  const data = JSON.parse(fs.readFileSync(jsonPath, "utf8"));

  const backendPkgs = data.backendPackages || [];
  const frontendPkgs = data.frontendPackages || [];
  const allPkgs = [...backendPkgs, ...frontendPkgs];
  const vulnerabilities = data.vulnerabilities || [];

  // 1. Calculate Component Stats
  const totalComponents = allPkgs.length;
  const libraryComponents = allPkgs.filter(p => p.type === "Library").length;
  const appComponents = totalComponents - libraryComponents;

  // 2. Calculate License Distribution
  const licenseCounts = {};
  allPkgs.forEach(pkg => {
    const lic = pkg.license || "Unknown";
    licenseCounts[lic] = (licenseCounts[lic] || 0) + 1;
  });

  const sortedLicenses = Object.entries(licenseCounts)
    .sort((a, b) => b[1] - a[1]);

  const uniqueLicensesCount = sortedLicenses.length;
  const mostCommonLicense = sortedLicenses[0]?.[0] || "Unknown";
  const secondMostCommonLicense = sortedLicenses[1]?.[0] || "Unknown";
  const unknownLicenseCount = licenseCounts["Unknown"] || 0;

  // Generate License LaTeX Rows
  const licenseRows = sortedLicenses.map(([lic, count]) => {
    return `${escapeLatex(lic)} & ${count} \\\\`;
  }).join("\n");

  // 3. Calculate Vulnerability Stats
  const criticalCount = vulnerabilities.filter(v => v.severity.toUpperCase() === "CRITICAL").length;
  const highCount = vulnerabilities.filter(v => v.severity.toUpperCase() === "HIGH").length;
  const mediumCount = vulnerabilities.filter(v => v.severity.toUpperCase() === "MEDIUM").length;
  const lowCount = vulnerabilities.filter(v => v.severity.toUpperCase() === "LOW").length;
  const negligibleCount = vulnerabilities.filter(v => ["NEGLIGIBLE", "UNKNOWN"].includes(v.severity.toUpperCase())).length;
  const totalVulnerabilities = vulnerabilities.length;

  const severityBadgeMap = {
    CRITICAL: "\\CriticalBadge",
    HIGH: "\\HighBadge",
    MEDIUM: "\\MediumBadge",
    LOW: "\\LowBadge",
    NEGLIGIBLE: "\\NegligibleBadge",
    UNKNOWN: "\\NegligibleBadge"
  };

  const getPriority = (sev) => {
    const s = sev.toUpperCase();
    if (s === "CRITICAL" || s === "HIGH") return "Immediate (Next Release)";
    if (s === "MEDIUM") return "High (Within 30 Days)";
    return "Medium (Next Scheduled Maintenance)";
  };

  const getActionText = (fixedVersion) => {
    return fixedVersion && fixedVersion !== "N/A" ? `Upgrade to version ${fixedVersion}` : "Apply vendor updates";
  };

  // Format Scan Date
  const dateOptions = { day: "2-digit", month: "long", year: "numeric" };
  const scanDate = new Date().toLocaleDateString("en-GB", dateOptions);

  // ==========================================
  // Update stats.tex
  // ==========================================
  const statsPath = path.join(__dirname, "chapters", "stats.tex");
  console.log(`✍️ Updating ${statsPath}...`);
  const statsTexContent = `\\newcommand{\\ProjectName}{ZeroWatch Sentinel Agent}
\\newcommand{\\ProjectVersion}{1.1.1}
\\newcommand{\\SbomFormat}{CycloneDX}
\\newcommand{\\SbomSpecVersion}{1.7}
\\newcommand{\\SbomGenerator}{Syft 1.46.0}
\\newcommand{\\VulScanner}{Grype 0.115.0 + ZeroWatch Agent Scan}
\\newcommand{\\TotalComponents}{${totalComponents}}
\\newcommand{\\LibraryComponents}{${libraryComponents}}
\\newcommand{\\AppComponents}{${appComponents}}
\\newcommand{\\UniqueLicenses}{${uniqueLicensesCount}}
\\newcommand{\\TotalVulnerabilities}{${totalVulnerabilities}}
\\newcommand{\\CriticalVuls}{${criticalCount}}
\\newcommand{\\HighVuls}{${highCount}}
\\newcommand{\\MediumVuls}{${mediumCount}}
\\newcommand{\\LowVuls}{${lowCount}}
\\newcommand{\\NegligibleVuls}{${negligibleCount}}
\\newcommand{\\ScanDate}{${scanDate}}
\\newcommand{\\ReportDate}{\\today}
\\newcommand{\\MostCommonLicense}{${mostCommonLicense}}
\\newcommand{\\SecondMostCommonLicense}{${secondMostCommonLicense}}
\\newcommand{\\UnknownLicenseCount}{${unknownLicenseCount}}
`;
  fs.writeFileSync(statsPath, statsTexContent, "utf8");

  // ==========================================
  // Helper for placeholder replacements
  // ==========================================
  const replacePlaceholder = (filePath, placeholder, replacement) => {
    if (!fs.existsSync(filePath)) {
      console.warn(`⚠️ Warning: File ${filePath} not found.`);
      return;
    }
    let content = fs.readFileSync(filePath, "utf8");
    content = content.replace(placeholder, replacement);
    fs.writeFileSync(filePath, content, "utf8");
  };

  // ==========================================
  // Update license distribution rows
  // ==========================================
  const filesWithLicenses = [
    path.join(__dirname, "chapters", "statistics.tex"),
    path.join(__dirname, "chapters", "license_analysis.tex"),
    path.join(__dirname, "chapters", "appendix.tex")
  ];
  filesWithLicenses.forEach(fp => {
    console.log(`✍️ Injecting license rows into ${path.basename(fp)}...`);
    replacePlaceholder(fp, /%\s*%LICENSE_DISTRIBUTION_ROWS%/g, licenseRows);
  });

  // ==========================================
  // Update dependency_inventory.tex
  // ==========================================
  const inventoryPath = path.join(__dirname, "chapters", "dependency_inventory.tex");
  console.log(`✍️ Injecting components table rows into ${path.basename(inventoryPath)}...`);

  // Use a representative sample of up to 120 components to prevent PDF bloat
  const samplePkgs = allPkgs.slice(0, 120);
  const componentRows = samplePkgs.map(pkg => {
    return `${escapeLatex(pkg.name)} & ${escapeLatex(pkg.version)} & ${escapeLatex(pkg.type)} & ${escapeLatex(pkg.license)} \\\\`;
  }).join("\n");
  replacePlaceholder(inventoryPath, /%\s*%REPRESENTATIVE_COMPONENTS_ROWS%/g, componentRows);

  // ==========================================
  // Update vulnerability_findings.tex
  // ==========================================
  const vulFindingsPath = path.join(__dirname, "chapters", "vulnerability_findings.tex");
  console.log(`✍️ Injecting vulnerability data into ${path.basename(vulFindingsPath)}...`);

  // Severity distribution text description
  let sevDistributionText = "";
  if (totalVulnerabilities === 0) {
    sevDistributionText = "The vulnerability assessment identified zero security vulnerabilities within the scanned dependencies.";
  } else {
    sevDistributionText = `The vulnerability assessment identified a total of ${totalVulnerabilities} vulnerabilities. Of these, ${criticalCount} are classified as Critical, ${highCount} as High, ${mediumCount} as Medium, ${lowCount} as Low, and ${negligibleCount} as Negligible severity findings.`;
  }
  replacePlaceholder(vulFindingsPath, /%\s*%SEVERITY_DISTRIBUTION_TEXT%/g, sevDistributionText);

  // Vulnerability table rows
  const vulTableRows = vulnerabilities.map(v => {
    const badge = severityBadgeMap[v.severity.toUpperCase()] || "\\NegligibleBadge";
    return `${escapeLatex(v.packageName)} & ${badge} & ${escapeLatex(v.packageVersion)} & ${escapeLatex(v.fixedVersion)} & ${escapeLatex(v.cveId)} \\\\`;
  }).join("\n");
  replacePlaceholder(vulFindingsPath, /%\s*%VULNERABILITY_TABLE_ROWS%/g, vulTableRows || "% No vulnerabilities found");

  // Vulnerability analysis sections
  const vulAnalysisSections = vulnerabilities.map(v => {
    const badge = severityBadgeMap[v.severity.toUpperCase()] || "\\NegligibleBadge";
    const recommendation = v.fixedVersion && v.fixedVersion !== "N/A"
      ? `Upgrade to version ${escapeLatex(v.fixedVersion)} or later.`
      : "Review public advisory and apply vendor mitigation recommendations.";
    return `\\subsection{${escapeLatex(v.cveId)}}

\\textbf{Affected Package} \\\\
${escapeLatex(v.packageName)}

\\vspace{0.2cm}
\\textbf{Severity} \\\\
${badge}

\\vspace{0.2cm}
\\textbf{Installed Version} \\\\
${escapeLatex(v.packageVersion)}

\\vspace{0.2cm}
\\textbf{Fixed Version} \\\\
${escapeLatex(v.fixedVersion)}

\\vspace{0.2cm}
\\textbf{Description} \\\\
${escapeLatex(v.description)}

\\vspace{0.2cm}
\\textbf{Recommendation} \\\\
${recommendation}

\\vspace{0.5cm}
\\color{ZWBorder}\\hrule height 0.6pt\\color{ZWDark}
\\vspace{0.5cm}
`;
  }).join("\n");
  replacePlaceholder(vulFindingsPath, /%\s*%VULNERABILITY_ANALYSIS_SECTIONS%/g, vulAnalysisSections || "% No vulnerability analysis details required");

  // Remediation Priority table rows
  const remediationRows = vulnerabilities.map(v => {
    const priority = getPriority(v.severity);
    const action = getActionText(v.fixedVersion);
    return `${escapeLatex(v.packageName)} & ${priority} & ${escapeLatex(action)} \\\\`;
  }).join("\n");
  replacePlaceholder(vulFindingsPath, /%\s*%REMEDIATION_PRIORITY_ROWS%/g, remediationRows || "% No remediation priorities required");

  // Key Observations
  let keyObservationsText = `\\item A total of ${totalVulnerabilities} vulnerabilities were identified.
\\item The software supply chain consists primarily of Python packages.
\\item ${mostCommonLicense} is the most commonly used open-source license.
\\item Continuous SBOM regeneration should accompany dependency updates.`;
  if (criticalCount > 0) {
    keyObservationsText = `\\item \\textbf{Immediate Remediation Required:} ${criticalCount} Critical vulnerabilities detected.
` + keyObservationsText;
  }
  if (highCount > 0) {
    keyObservationsText = `\\item \\textbf{Elevated Action Required:} ${highCount} High vulnerabilities detected.
` + keyObservationsText;
  }
  replacePlaceholder(vulFindingsPath, /%\s*%KEY_OBSERVATIONS_ITEMS%/g, keyObservationsText);

  // Overall Risk Text
  let overallRiskText = "";
  if (criticalCount > 0) {
    overallRiskText = `Based on the vulnerability assessment results, the overall software supply chain risk for the \\textbf{\\ProjectName} is assessed as \\textbf{Critical}. There are ${criticalCount} Critical vulnerabilities identified that require immediate remediation to prevent security exposure.`;
  } else if (highCount > 0) {
    overallRiskText = `Based on the vulnerability assessment results, the overall software supply chain risk for the \\textbf{\\ProjectName} is assessed as \\textbf{Moderate}. Although High severity vulnerabilities were identified, they can be mitigated through package updates to available fixed versions.`;
  } else {
    overallRiskText = `Based on the vulnerability assessment results, the overall software supply chain risk for the \\textbf{\\ProjectName} is assessed as \\textbf{Low}. No Critical or High vulnerabilities were identified in the scanned packages.`;
  }
  replacePlaceholder(vulFindingsPath, /%\s*%OVERALL_RISK_TEXT%/g, overallRiskText);

  // Summary Text
  let summaryText = "";
  if (totalVulnerabilities === 0) {
    summaryText = `The Grype and ZeroWatch Agent Audit Software Composition Analysis identified zero vulnerabilities affecting the dependencies of the \\textbf{\\ProjectName}. The overall security posture remains clean and compliant.`;
  } else {
    summaryText = `The Grype and ZeroWatch Agent Audit Software Composition Analysis identified vulnerabilities affecting third-party dependencies used by the \\textbf{\\ProjectName}. Applying the recommended dependency updates and incorporating continuous vulnerability scanning will keep the agent secure.`;
  }
  replacePlaceholder(vulFindingsPath, /%\s*%SUMMARY_TEXT%/g, summaryText);

  // ==========================================
  // Dynamic recommendations.tex, dashboard.tex, statistics.tex and findings
  // ==========================================
  const recommendationsPath = path.join(__dirname, "chapters", "recommendations.tex");
  const dashboardPath = path.join(__dirname, "chapters", "dashboard.tex");
  const statisticsPath = path.join(__dirname, "chapters", "statistics.tex");

  // Immediate Remediation Text
  let immediateRemediationText = "";
  if (totalVulnerabilities === 0) {
    immediateRemediationText = "The vulnerability assessment did not identify any immediate package security vulnerabilities.";
  } else if (criticalCount > 0 || highCount > 0) {
    const severityParts = [];
    if (criticalCount > 0) severityParts.push(`${criticalCount} Critical`);
    if (highCount > 0) severityParts.push(`${highCount} High`);
    immediateRemediationText = `The vulnerability assessment identified ${severityParts.join(" and ")} severity vulnerabilities. These issues should be addressed before the next production release.`;
  } else {
    immediateRemediationText = "The vulnerability assessment identified only Medium or Low severity vulnerabilities. These issues should be addressed as part of regular software maintenance.";
  }

  // Immediate Remediation Items
  const immediateRemediationItems = vulnerabilities
    .filter(v => ["CRITICAL", "HIGH"].includes(v.severity.toUpperCase()))
    .map(v => {
      const pkgName = escapeLatex(v.packageName);
      const pkgVersion = escapeLatex(v.packageVersion);
      const fixedVersion = escapeLatex(v.fixedVersion);
      if (fixedVersion && fixedVersion !== "N/A") {
        return `\\item Upgrade \\texttt{${pkgName}} from version ${pkgVersion} to version ${fixedVersion} or later.`;
      } else {
        return `\\item Apply vendor updates or mitigation recommendations for \\texttt{${pkgName}} (version ${pkgVersion}).`;
      }
    });

  if (immediateRemediationItems.length === 0) {
    immediateRemediationItems.push("\\item No immediate package upgrades are required.");
  }
  const immediateRemediationItemsText = immediateRemediationItems.join("\n");

  // Recommendations Summary
  const recommendationsSummaryText = `The \\textbf{\\ProjectName} already demonstrates a strong foundation for software supply chain security through the generation of a CycloneDX Software Bill of Materials using Syft and the execution of Software Composition Analysis using Grype and the ZeroWatch Agent Audit Scan. The vulnerability assessment identified ${totalVulnerabilities === 0 ? 'zero vulnerabilities' : totalVulnerabilities + ' vulnerabilities'} in total, which can be remediated through the recommended dependency updates and security configurations.`;

  // Dashboard Overview
  const dashboardOverviewText = `This high-level dashboard shows that while the codebase utilizes a number of third-party libraries (\\TotalComponents\\ components under \\UniqueLicenses\\ unique licenses), the security scanner identified ${totalVulnerabilities === 0 ? 'no vulnerabilities' : 'only ' + totalVulnerabilities + ' vulnerabilities'}. All identified vulnerabilities are slated for remediation.`;

  // Statistics Vulnerability Summary
  const statisticsVulnerabilitySummaryText = `The vulnerability assessment identified ${totalVulnerabilities} vulnerabilities. Of these, ${criticalCount} are Critical, ${highCount} are High, ${mediumCount} are Medium, ${lowCount} are Low, and ${negligibleCount} are Negligible. These findings provide a snapshot of the current security posture and help prioritize remediation activities.`;

  // Vulnerability Severity Summary
  const vulnerabilitySeveritySummaryText = `The assessment indicates that the identified vulnerabilities consist of ${criticalCount} Critical, ${highCount} High, ${mediumCount} Medium, ${lowCount} Low, and ${negligibleCount} Negligible findings. Remediation efforts should prioritize higher severity issues first.`;

  replacePlaceholder(recommendationsPath, /%\s*%IMMEDIATE_REMEDIATION_TEXT%/g, immediateRemediationText);
  replacePlaceholder(recommendationsPath, /%\s*%IMMEDIATE_REMEDIATION_ITEMS%/g, immediateRemediationItemsText);
  replacePlaceholder(recommendationsPath, /%\s*%RECOMMENDATIONS_SUMMARY_TEXT%/g, recommendationsSummaryText);
  replacePlaceholder(dashboardPath, /%\s*%DASHBOARD_OVERVIEW_TEXT%/g, dashboardOverviewText);
  replacePlaceholder(statisticsPath, /%\s*%STATISTICS_VULNERABILITY_SUMMARY_TEXT%/g, statisticsVulnerabilitySummaryText);
  replacePlaceholder(vulFindingsPath, /%\s*%VULNERABILITY_SEVERITY_SUMMARY_TEXT%/g, vulnerabilitySeveritySummaryText);

  console.log("✅ All LaTeX report chapters updated successfully!\n");
}

try {
  run();
} catch (e) {
  console.error("❌ Exception during LaTeX update:", e);
  process.exit(1);
}
