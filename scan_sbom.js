/**
 * scan_sbom.js
 * 
 * Standalone CLI script to:
 *   1. Dynamically run Syft to generate SBOM for the Endpoint Agent codebase.
 *   2. Scan the SBOM against the local CVE database.
 *   3. Run Grype scan on the generated SBOM.
 *   4. Merge all findings (DB + Grype) and present a unified report.
 *   5. Clean up temporary files.
 * 
 * Usage:
 *   node scan_sbom.js
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
require("dotenv").config();
const mongoose = require("mongoose");

// Parse CycloneDX components into standard package list
const parseCycloneDXComponents = (jsonData) => {
  let list = [];
  if (jsonData && typeof jsonData === "object" && Array.isArray(jsonData.components)) {
    for (const comp of jsonData.components) {
      if (comp && comp.name) {
        let license = "Unknown";
        if (Array.isArray(comp.licenses) && comp.licenses.length > 0) {
          const licObj = comp.licenses[0].license;
          if (licObj) {
            license = licObj.id || licObj.name || "Unknown";
          }
        }
        let type = comp.type ? String(comp.type) : "library";
        type = type.charAt(0).toUpperCase() + type.slice(1);
        list.push({
          name: String(comp.name).trim(),
          version: String(comp.version || "").trim(),
          type: type,
          license: license,
        });
      }
    }
  }
  return list.filter(s => s.name);
};

// Check if a command is available on system path
const isCommandAvailable = (cmd) => {
  try {
    execSync(`${cmd} --version`, { stdio: "ignore" });
    return true;
  } catch (err) {
    return false;
  }
};

async function run() {
  // Define Scan Directories
  const agentPath = __dirname;
  const tempAgentSbom = path.join(__dirname, "temp-agent-sbom.json");

  console.log("="?.repeat(80));
  console.log("🔍 DYNAMIC SECURITY SCANNER FOR AGENT (Syft + Grype + Database)");
  console.log("="?.repeat(80) + "\n");

  // Verify Syft & Grype availability
  if (!isCommandAvailable("syft")) {
    console.error("❌ Error: 'syft' is not installed or not available on system PATH.");
    console.log("Please install Syft first (e.g. winget install anchore.syft or via curl/powershell).");
    process.exit(1);
  }
  if (!isCommandAvailable("grype")) {
    console.error("❌ Error: 'grype' is not installed or not available on system PATH.");
    process.exit(1);
  }

  // 1. Generate SBOM using Syft
  console.log("📦 Generating SBOM for Agent codebase...");
  try {
    // Exclude build, dist, git, github, pycache, and sbom_generation directories to prevent scanning CI configs, output binaries or config templates
    const excludeFlags = [
      '**/build/**',
      '**/dist/**',
      '**/__pycache__/**',
      '**/.git/**',
      '**/.github/**',
      '**/sbom_generation/**',
      '**/temp-*.json'
    ].map(pattern => `--exclude "${pattern}"`).join(" ");

    execSync(`syft "${agentPath}" -o cyclonedx-json ${excludeFlags} > "${tempAgentSbom}"`, { stdio: "inherit" });
    console.log(`✅ Agent SBOM generated successfully.\n`);
  } catch (err) {
    console.error(`❌ Failed to generate Agent SBOM: ${err.message}`);
    process.exit(1);
  }

  // Parse generated SBOM
  let agentPackages = [];
  if (fs.existsSync(tempAgentSbom)) {
    try {
      agentPackages = parseCycloneDXComponents(JSON.parse(fs.readFileSync(tempAgentSbom, "utf8")));
    } catch (err) {
      console.warn(`⚠️ Warning: Failed to parse Agent SBOM: ${err.message}`);
    }
  }

  // 2. Scan Local Database
  const dbMatches = [];
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.warn("⚠️ Warning: MONGO_URI is not set in .env. Skipping local DB matching.\n");
  } else {
    try {
      console.log(`🔌 Connecting to CVE database...`);
      await mongoose.connect(uri);
      const db = mongoose.connection.db;
      console.log("✅ Connected to CVE database successfully.\n");

      const distinctProducts = await db.collection("unified_cves").distinct("cpe.product");
      const productSet = new Set(distinctProducts.filter(Boolean).map(p => p.toLowerCase()));

      const scanPackages = async (packages, scopeName) => {
        console.log(`🔎 Database lookup for ${packages.length} packages in ${scopeName}...`);
        for (const pkg of packages) {
          const pkgNameLower = pkg.name.toLowerCase();
          const cleanName = pkgNameLower.replace(/^@[^/]+\//, "");

          let matchedProduct = null;
          if (productSet.has(pkgNameLower)) {
            matchedProduct = pkgNameLower;
          } else if (productSet.has(cleanName)) {
            matchedProduct = cleanName;
          }

          if (matchedProduct) {
            const query = {
              $or: [
                { "cpe.product": matchedProduct },
                { "vulnerable_cpe.product": matchedProduct }
              ]
            };
            const cves = await db.collection("unified_cves").find(query).toArray();
            for (const cve of cves) {
              dbMatches.push({
                scope: scopeName,
                packageName: pkg.name,
                packageVersion: pkg.version,
                matchedProduct: matchedProduct,
                cveId: cve.cve_id,
                severity: cve.severity || "UNKNOWN",
                cvssScore: cve.cvss_score || null,
                fixedVersion: "N/A",
                description: cve.description || ""
              });
            }
          }

          // Special rule for crypto modules
          if (pkgNameLower.includes("crypto") && productSet.has("crypto")) {
            const cryptoCves = await db.collection("unified_cves").find({
              $or: [
                { "cpe.product": "crypto" },
                { "vulnerable_cpe.product": "crypto" }
              ]
            }).toArray();
            for (const cve of cryptoCves) {
              dbMatches.push({
                scope: scopeName,
                packageName: pkg.name,
                packageVersion: pkg.version,
                matchedProduct: "crypto",
                cveId: cve.cve_id,
                severity: cve.severity || "UNKNOWN",
                cvssScore: cve.cvss_score || null,
                fixedVersion: "N/A",
                description: cve.description || ""
              });
            }
          }
        }
      };

      await scanPackages(agentPackages, "Agent");
      console.log(`✅ DB scan complete. Found ${dbMatches.length} matching vulnerabilities.\n`);
    } catch (dbErr) {
      console.warn(`⚠️ Warning: Database scanning failed: ${dbErr.message}\n`);
    }
  }

  // 3. Scan with Grype CLI
  const grypeMatches = [];
  const runGrypeOnSbom = (sbomPath, scopeName) => {
    console.log(`🛡️ Running Grype scanner on ${scopeName} SBOM...`);
    try {
      const grypeOutput = execSync(`grype "${sbomPath}" -o json`, { maxBuffer: 25 * 1024 * 1024, encoding: "utf8" });
      const parsedGrype = JSON.parse(grypeOutput);
      if (parsedGrype && Array.isArray(parsedGrype.matches)) {
        for (const match of parsedGrype.matches) {
          if (match.vulnerability && match.artifact) {
            const fixedVersion = (match.vulnerability.fix && Array.isArray(match.vulnerability.fix.versions) && match.vulnerability.fix.versions.length > 0) ? match.vulnerability.fix.versions[0] : "N/A";
            const cvssScore = match.vulnerability.cvss && match.vulnerability.cvss[0] ?
                              match.vulnerability.cvss[0].metrics?.baseScore : null;
            grypeMatches.push({
              scope: scopeName,
              packageName: match.artifact.name,
              packageVersion: match.artifact.version,
              cveId: match.vulnerability.id,
              severity: match.vulnerability.severity ? match.vulnerability.severity.toUpperCase() : "UNKNOWN",
              cvssScore: cvssScore,
              fixedVersion: fixedVersion,
              description: match.vulnerability.description || ""
            });
          }
        }
      }
      console.log(`✅ Grype scan of ${scopeName} completed.\n`);
    } catch (err) {
      console.warn(`⚠️ Warning: Grype scanning failed for ${scopeName}: ${err.message}\n`);
    }
  };

  if (fs.existsSync(tempAgentSbom)) {
    runGrypeOnSbom(tempAgentSbom, "Agent");
  }

  // 4. Clean up temporary files
  console.log("🧹 Cleaning up temporary SBOM files...");
  if (fs.existsSync(tempAgentSbom)) fs.unlinkSync(tempAgentSbom);
  console.log("✅ Cleanup completed.\n");

  // 5. Merge results
  const mergedMap = new Map();

  for (const m of dbMatches) {
    const key = `${m.scope}::${m.packageName}::${m.cveId}`.toLowerCase();
    mergedMap.set(key, {
      scope: m.scope,
      packageName: m.packageName,
      packageVersion: m.packageVersion,
      cveId: m.cveId,
      severity: m.severity,
      cvssScore: m.cvssScore,
      fixedVersion: m.fixedVersion || "N/A",
      description: m.description,
      sources: ["Local Database"]
    });
  }

  for (const m of grypeMatches) {
    const key = `${m.scope}::${m.packageName}::${m.cveId}`.toLowerCase();
    if (mergedMap.has(key)) {
      const existing = mergedMap.get(key);
      if (!existing.sources.includes("Grype Scanner")) {
        existing.sources.push("Grype Scanner");
      }
      if (!existing.cvssScore) existing.cvssScore = m.cvssScore;
      if (!existing.description) existing.description = m.description;
      if (existing.fixedVersion === "N/A" && m.fixedVersion !== "N/A") {
        existing.fixedVersion = m.fixedVersion;
      }
    } else {
      mergedMap.set(key, {
        scope: m.scope,
        packageName: m.packageName,
        packageVersion: m.packageVersion,
        cveId: m.cveId,
        severity: m.severity,
        cvssScore: m.cvssScore,
        fixedVersion: m.fixedVersion || "N/A",
        description: m.description,
        sources: ["Grype Scanner"]
      });
    }
  }

  const mergedList = Array.from(mergedMap.values());
  console.log(`📊 Unified Scan Complete! Found ${mergedList.length} unique vulnerabilities.\n`);

  // Save scan report results to JSON file for LaTeX report builder
  // We save agentPackages to backendPackages and set frontendPackages to [] for backward compatibility with update_latex.js
  const scanOutputPath = process.env.SCAN_OUTPUT_PATH || path.join(__dirname, "scan-output.json");
  console.log(`💾 Saving scan report results to ${scanOutputPath}...`);
  fs.writeFileSync(scanOutputPath, JSON.stringify({
    backendPackages: agentPackages,
    frontendPackages: [],
    vulnerabilities: mergedList
  }, null, 2));

  if (mergedList.length > 0) {
    console.log("="?.repeat(80));
    console.log(`🛡️  UNIFIED VULNERABILITY REPORT (Database + Grype)`);
    console.log("="?.repeat(80));

    // Group by Scope
    const scopes = { "Agent": [] };
    for (const match of mergedList) {
      if (!scopes[match.scope]) scopes[match.scope] = [];
      scopes[match.scope].push(match);
    }

    for (const [scopeName, scopeList] of Object.entries(scopes)) {
      if (scopeList.length === 0) continue;

      console.log(`\n📂 [Component: ${scopeName.toUpperCase()}] (${scopeList.length} vulnerabilities)`);
      console.log("-"?.repeat(40));

      // Group by Package Name within Scope
      const pkgGroups = {};
      for (const m of scopeList) {
        if (!pkgGroups[m.packageName]) pkgGroups[m.packageName] = [];
        pkgGroups[m.packageName].push(m);
      }

      for (const [pkgName, list] of Object.entries(pkgGroups)) {
        console.log(`  📦 Package: ${pkgName} (${list[0].packageVersion})`);
        for (const item of list) {
          const sourceStr = item.sources.join(" & ");
          console.log(`     ├─ 🔴 [${item.severity}] ${item.cveId} (CVSS: ${item.cvssScore || "N/A"}) [Source: ${sourceStr}]`);
          console.log(`     │  Desc: ${item.description ? item.description.slice(0, 120) : "No description"}...`);
        }
      }
    }
    console.log("\n" + "="?.repeat(80));
  } else {
    console.log("🎉 No matching vulnerabilities found in local database or Grype scanner for the Agent.");
  }

  process.exit(0);
}

run().catch(err => {
  console.error("❌ Execution Error:", err);
  process.exit(1);
});
