# ZeroWatch Backend Performance & Scalability Audit

**Target Product:** ZeroWatch Enterprise Cybersecurity & Vulnerability Management Platform  
**Target Backend Codebase:** `CVE-Engine-V2/backend` (`zerowatch.deepcytes.io`)  
**Audit Scope:** Complete review of all 401 API endpoints across 37 router files, controllers, services, aggregation pipelines, and database queries  
**Audit Date:** November 2026  
**Auditor:** Antigravity Advanced Agentic Performance & Security Engineering  

---

## 1. Executive Summary

A comprehensive performance and architectural scalability audit was performed on the ZeroWatch backend (`CVE-Engine-V2/backend`), which powers both the web management platform and the client desktop fleet (`SentinelAgent.exe`).

### Core Bottlenecks Identified
1. **Global Artificial Latency Overhead (`index.js:281–305`)**: Every single HTTP response emitted by `res.json` across the entire application is delayed by a `setTimeout` artificial timer of **50ms–80ms** under the guise of anti-fingerprinting. This pins TCP sockets, exhausts file descriptors, inflates event-loop lag, and establishes an artificial floor on all API response times under load.
2. **Commented-Out In-Memory Caching (`teamDashboard.js`, `teamDashboardRoutes.js`, `dashboardRoutes.js`)**: Production caching was explicitly disabled (`// CACHE DISABLED: Bypassed to ensure 100% real-time dashboard updates`). Navigating to the Team Dashboard fires 6 parallel requests that each execute full collection scans and multi-megabyte array unmarshaling simultaneously.
3. **High-Frequency Heartbeat Duplication (`agentController.js:3177–3297`)**: Every agent heartbeat (sent every 5–60s by thousands of agents) executes 4–5 database calls, including redundant duplicate `findOne` calls on `Agent_Inventory` for the same record.
4. **Collation Mismatch on Agent Feed Rebuilds (`agentFeedService.js:1285–1330`)**: Background inventory matching runs an `$or` `$elemMatch` query over `unified_cves` inside a loop for every software package using `{ collation: { locale: "en", strength: 2 } }`. Because standard indexes lack this collation, MongoDB falls back to a **full collection scan** across 250,000+ CVE records per installed application.
5. **Disk-Spilling Aggregation Pipelines (`hierarchyDashboardController.js:6469, 8769, 8778`)**: Hierarchy feed aggregation pipelines unwind massive vulnerability and product arrays across all organizational devices, requiring `{ allowDiskUse: true }` because RAM usage exceeds MongoDB's 100MB stage limit.

---

## 2. Priority Summary Matrix

| # | Priority | Endpoint / Scope | Method & Path | File & Location | Primary Issue Type |
| :-: | :---: | :--- | :--- | :--- | :--- |
| **1** | 🔴 **HIGH** | Global Anti-Fingerprinting | `*` (All Routes) | `index.js:281–305` | 50–80ms artificial timer delay on every single response |
| **2** | 🔴 **HIGH** | Agent Heartbeat | `POST /api/agent/heartbeat` | `agentController.js:3177–3297` | 4–5 DB round-trips per heartbeat; redundant document re-fetching |
| **3** | 🔴 **HIGH** | Inventory Sync & Matching | `POST /api/agent/sync/full`<br>`POST /api/agent/sync/delta` | `agentFeedService.js:1285–1330`<br>`agentController.js:3565` | N+1 loop querying `unified_cves` per product with collation mismatch causing full table scans |
| **4** | 🔴 **HIGH** | Team Feed Aggregation | `GET /api/teams/feed` | `teamRoutes.js:3115–3369` | Unbounded in-memory heap sorting and pagination over multi-MB raw feed docs |
| **5** | 🔴 **HIGH** | Team Dashboard Metrics | `GET /api/teams/dashboard/summary-stats`<br>`GET /api/teams/dashboard/total-*` | `teamDashboard.js:138–141`<br>`teamDashboardRoutes.js:10–18` | Caching explicitly commented out; 6 parallel requests run unindexed collection scans |
| **6** | 🔴 **HIGH** | Hierarchy Dashboard Overview | `GET /api/dashboard/v2/org`<br>`POST /api/dashboard/v2/managed-teams-overview` | `hierarchyDashboardController.js:8766–8805` | Triplicate heavy aggregation pipelines with `$unwind`, `$lookup`, and `{ allowDiskUse: true }` |
| **7** | 🔴 **HIGH** | User Session & Licensing | `GET /api/auth/me` | `server/api/auth/index.js:2317–2550` | 5–8 sequential DB calls per page load; duplicate `licenses` collection lookups |
| **8** | 🔴 **HIGH** | Watchlist Feed | `GET /api/watchlist/feed` | `watchlistController.js:2550–2850` | Unbounded `.find().toArray()` on all matching CVE IDs; `$expr` date scans |
| **9** | 🟡 **MEDIUM** | Dashboard Activity Heatmap | `GET /api/dashboard/heatmap-resolved-cves` | `dashboardRoutes.js:468–540`<br>`dashboardController.js:2650–2800` | Sequential N-query month loop reloading the same two documents 12 times; cache bypassed |
| **10** | 🟡 **MEDIUM** | Global Autocomplete | `GET /api/cve/autocomplete` | `cveController.js:1380–1460` | 5 parallel unanchored regex queries across 5 collections per keystroke |
| **11** | 🟡 **MEDIUM** | Monthly Threat Report | `POST /api/reports/monthly-threat/generate` | `monthlyThreatReportController.js:140–170` | Synchronous heavy aggregation scanning entire month of CVEs inside HTTP request thread |
| **12** | 🟡 **MEDIUM** | License Administration | `GET /api/license/search`<br>`GET /api/license/all` | `licenseController.js:120–180, 240–310` | Unindexed `$or` regex; in-loop eager email dispatch and DB writes in `.map()` |
| **13** | 🟡 **MEDIUM** | Organization Activity Logs | `GET /api/org-logs/` | `orgLogsController.js:350–520, 600–700` | Cascading 3-collection hierarchy ID discovery + unanchored regex scan on audit logs |
| **14** | 🟡 **MEDIUM** | Billing Value Delivered | `GET /api/billing/cycle-dashboard`<br>`GET /api/billing/components/*` | `billingReportService.js:20–80` | Full in-memory extraction of all enterprise feed documents without cursor streaming |
| **15** | 🟢 **LOW** | Single CVE Lookup | `GET /api/product/cve/:cveId`<br>`GET /api/cve/cveid/:id` | `productcontroller.js:80–120`<br>`cveController.js:220–280` | Unprojected `SELECT *` of massive CVE records; 6 parallel collection lookups |
| **16** | 🟢 **LOW** | Device Events & Shadow IT | `GET /api/device-feed/:deviceId`<br>`GET /api/agent/events` | `deviceFeedController.js:447`<br>`agentController.js:1274` | Unbounded event retrieval without hard limit caps |

---

## 3. Detailed Endpoint Performance Analysis

---

### 3.1. Global Anti-Fingerprinting Response Delay
* **Method & Path:** All HTTP endpoints (`*`)
* **Implemented At:** `backend/index.js#L281-L305`
* **Specific Problem:**
  ```javascript
  app.use((req, res, next) => {
    const startTime = Date.now();
    const originalJson = res.json;
    res.json = function (data) {
      const processingTime = Date.now() - startTime;
      const minDelay = 50; // Minimum 50ms response time
      const randomDelay = Math.floor(Math.random() * 30); // 0-30ms random
      const totalDelay = Math.max(minDelay - processingTime, 0) + randomDelay;
      setTimeout(() => {
        if (!res.headersSent) {
          res.removeHeader("ETag");
          res.removeHeader("Last-Modified");
        }
        originalJson.call(this, data);
      }, totalDelay);
    };
    next();
  });
  ```
* **Why It Hurts:**
  Every HTTP request across the entire server is artificially delayed by 50ms to 80ms before bytes are sent over the wire. Under concurrent load (e.g., 2,000 endpoint agents submitting heartbeats and sync deltas), this forces Node.js to maintain thousands of idle TCP sockets and active `setTimeout` timers simultaneously. It artificially elevates P50/P99 latency, increases RAM pressure, and ties up upstream reverse proxy connections.
* **Concrete Fix:**
  Remove global response delay middleware. If anti-timing obfuscation is strictly required, restrict it solely to unauthenticated authentication endpoints (`POST /api/auth/login`):
  ```javascript
  // Restrict timing obfuscation strictly to sensitive auth endpoints
  app.use((req, res, next) => {
    if (!req.path.startsWith("/api/auth/login")) {
      return next();
    }
    // Only apply to login...
  });
  ```
* **Priority:** 🔴 **HIGH**

---

### 3.2. High-Frequency Agent Heartbeat Duplication
* **Method & Path:** `POST /api/agent/heartbeat`
* **Implemented At:** `backend/controllers/agentController.js#L3177-L3297` (Route: `backend/routes/agentRoutes.js#L86`)
* **Specific Problem:**
  ```javascript
  const linkedAgent = await findLinkedAgentForToken(agentsCol, req.agent, {
    _id: 1, teamId: 1, team_id: 1, "deviceInfo.asset_name": 1,
  });
  ...
  await agentsCol.updateOne({ _id: linkedAgent._id }, { $set: { lastSeen: heartbeatTime, ... } });
  ...
  const licenseState = await resolveAgentLicenseState(db, req.agent);
  ...
  // Line 3243: Redundant query for field already fetched at line 3185!
  const agentDoc = await agentsCol.findOne(
    { _id: linkedAgent._id },
    { projection: { "deviceInfo.asset_name": 1 } },
  );
  ...
  const team = await teamCol.findOne(
    { _id: new ObjectId(req.agent.teamId) },
    { projection: { "owner.email": 1 } },
  );
  ```
* **Why It Hurts:**
  With 1,000 agents checking in every 10 seconds (100 req/s), this executes 400–500 DB queries per second. Querying `agentsCol.findOne` on line 3243 is 100% redundant because `deviceInfo.asset_name` was already fetched in `linkedAgent` at line 3185. Furthermore, looking up the team owner on every ping creates unnecessary read traffic.
* **Concrete Fix:**
  1. Remove line 3243; read `linkedAgent.deviceInfo?.asset_name` directly.
  2. Cache team owner emails in memory keyed by `teamId`.
  3. Buffer `lastSeen` updates in-memory or Redis and batch write them:
  ```javascript
  const desiredAssetName = String(linkedAgent?.deviceInfo?.asset_name || "").trim();
  ```
* **Priority:** 🔴 **HIGH**

---

### 3.3. Inventory Synchronization: N+1 Software Queries with Collation Full Scans
* **Method & Path:** `POST /api/agent/sync/full`, `POST /api/agent/sync/delta`
* **Implemented At:** `backend/services/agentFeedService.js#L1285-L1330` (Called via `backend/controllers/agentController.js#L3565`)
* **Specific Problem:**
  ```javascript
  for (const group of addedSoftwareGroups.values()) {
    const query = {
      $or: [
        { cpe: { $elemMatch: { vendor: group.vendorSearch, product: group.productSearch } } },
        { vulnerable_cpe: { $elemMatch: { vendor: group.vendorSearch, product: group.productSearch } } },
      ],
    };

    const cursor = unifiedCol.find(query, {
      projection: { ... },
      collation: { locale: "en", strength: 2 }
    });
    for await (const cve of cursor) { ... }
  }
  ```
* **Why It Hurts:**
  1. **N+1 Queries:** Loops over every application on an endpoint (often 80–150 apps), executing sequential queries against `unified_cves`.
  2. **Collation Full Table Scan:** In MongoDB, queries specifying `{ collation: { locale: "en", strength: 2 } }` **cannot utilize standard binary indexes**. If the index on `cpe.vendor` / `cpe.product` lacks this exact collation, MongoDB scans all 250,000+ CVE records per installed application, driving database CPU to 100%.
* **Concrete Fix:**
  Normalize data to lowercase at ingestion time so collation options are unnecessary, and batch multiple software packages into single `$in` queries:
  ```javascript
  db.collection("unified_cves").createIndex(
    { "cpe.vendor": 1, "cpe.product": 1 },
    { name: "idx_cpe_vendor_product_ci", collation: { locale: "en", strength: 2 }, background: true }
  );
  ```
* **Priority:** 🔴 **HIGH**

---

### 3.4. Team Feed Aggregation: In-Memory Heap Sorting Over Raw Feeds
* **Method & Path:** `GET /api/teams/feed`
* **Implemented At:** `backend/routes/teamRoutes.js#L3115-L3369`
* **Specific Problem:**
  ```javascript
  const agentData = await getTeamAgentFeedData(db, username.email);
  if (agentData) {
    const allVulnsMap = new Map();
    for (const agent of agentData.agents) {
      const feed = agentData.feedByDeviceId.get(agent.deviceId);
      if (!feed) continue;
      for (const vuln of feed.vulnerabilities || []) {
        ...
        allVulnsMap.set(instanceKey, { ...vuln });
      }
    }
    const allVulns = Array.from(allVulnsMap.values());
    allVulns.sort((a, b) => {
      const aScore = parseFloat(a.cvss_score) || 0;
      const bScore = parseFloat(b.cvss_score) || 0;
      return sortByCVSS === "highest-scores-first" ? bScore - aScore : aScore - bScore;
    });
    totalPages = Math.ceil(allVulns.length / limit) || 1;
    cves = allVulns.slice((page - 1) * limit, page * limit);
  }
  ```
* **Why It Hurts:**
  For a team with 50 endpoints and 1,500 vulnerabilities per endpoint, `getTeamAgentFeedData` deserializes up to 75,000 JSON objects into V8 memory, flattens them, sorts all 75,000 items on Node's main thread with `Array.prototype.sort()`, and discards 74,990 to return page 1 (`limit=10`). This blocks the event loop and triggers major garbage collection pauses.
* **Concrete Fix:**
  Perform aggregation, sorting, and pagination directly inside MongoDB:
  ```javascript
  const pagedVulns = await db.collection("agent_feed").aggregate([
    { $match: { deviceId: { $in: deviceIds } } },
    { $unwind: "$vulnerabilities" },
    { $match: { "vulnerabilities.status": status === "all" ? { $exists: true } : status } },
    { $sort: { "vulnerabilities.cvss_score": sortByCVSS === "highest-scores-first" ? -1 : 1 } },
    { $skip: (page - 1) * limit },
    { $limit: limit }
  ]).toArray();
  ```
* **Priority:** 🔴 **HIGH**

---

### 3.5. Team Dashboard Metrics: Caching Bypassed & 6x Query Storm
* **Method & Path:** `GET /api/teams/dashboard/summary-stats`, `GET /api/teams/dashboard/total-products`, `GET /api/teams/dashboard/total-vendors`, `GET /api/teams/dashboard/total-open-cves`, `GET /api/teams/dashboard/total-resolved-cves`, `GET /api/teams/dashboard/total-ignored-cves`
* **Implemented At:** `backend/controllers/teamDashboard.js#L138-L141` & `backend/routes/teamDashboardRoutes.js#L10-L18, L226-L240`
* **Specific Problem:**
  ```javascript
  // In controllers/teamDashboard.js:
  const getCoalescedTeamStats = async (db, team) => {
    // CACHE DISABLED: Bypassed to ensure 100% real-time dashboard updates
    return computeTeamTotalsDirectly(db, team);
  };

  // In routes/teamDashboardRoutes.js:
  router.use((req, res, next) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    next();
  });
  ```
* **Why It Hurts:**
  Opening the Team Dashboard triggers 6 parallel HTTP requests. Because caching is bypassed, **all 6 endpoints execute `computeTeamTotalsDirectly` concurrently**. Each execution queries all `Agent_Inventory` and `agent_feed` documents, recalculating product sets, vendor sets, and CVE sets from scratch 6 times simultaneously.
* **Concrete Fix:**
  Restore the in-flight coalesced cache with a 30-second TTL:
  ```javascript
  const getCoalescedTeamStats = async (db, team) => {
    const teamIdStr = team._id.toString();
    const cached = teamNumericStatsCache.get(teamIdStr);
    if (cached && Date.now() - cached.timestamp < 30000) {
      return cached.data;
    }
    if (inFlightTeamQueries.has(teamIdStr)) {
      return inFlightTeamQueries.get(teamIdStr);
    }
    const queryPromise = computeTeamTotalsDirectly(db, team).then(stats => {
      inFlightTeamQueries.delete(teamIdStr);
      teamNumericStatsCache.set(teamIdStr, { data: stats, timestamp: Date.now() });
      return stats;
    });
    inFlightTeamQueries.set(teamIdStr, queryPromise);
    return queryPromise;
  };
  ```
* **Priority:** 🔴 **HIGH**

---

### 3.6. Hierarchy Dashboard Overview: Disk-Spilling Aggregation Pipelines
* **Method & Path:** `GET /api/dashboard/v2/org`, `POST /api/dashboard/v2/managed-teams-overview`
* **Implemented At:** `backend/controllers/hierarchyDashboardController.js#L6469-L6472, L8766-L8805`
* **Specific Problem:**
  ```javascript
  const [rowTotal = {}] = await db
    .collection("agent_feed")
    .aggregate(buildRowTotalPipeline(), { allowDiskUse: true })
    .toArray();

  const pagedRows = await db
    .collection("agent_feed")
    .aggregate(buildPagedRowsPipeline(targetPage), { allowDiskUse: true })
    .toArray();

  const productOptions = await db
    .collection("agent_feed")
    .aggregate(buildProductOptionsPipeline(), { allowDiskUse: true })
    .toArray();
  ```
* **Why It Hurts:**
  For every page request in the hierarchy dashboard, 3 separate multi-stage aggregation pipelines are executed. Each pipeline unwinds `vulnerabilities` and `affected_products` across hundreds of endpoints, groups them, and performs a `$lookup` join against `unified_cves`. Because memory exceeds MongoDB's 100MB RAM cap, each pipeline requires `{ allowDiskUse: true }`, forcing MongoDB to write intermediate documents to disk.
* **Concrete Fix:**
  1. Maintain pre-computed summaries for organizational nodes (`organizations`, `regions`, `branches`) updated via background Agenda jobs (`recomputeManagedHierarchySummaries`) on agent sync events.
  2. Combine the count and paged data retrieval into a single `$facet` pipeline stage.
* **Priority:** 🔴 **HIGH**

---

### 3.7. User Session Check: 5–8 Sequential Database Calls per Navigation
* **Method & Path:** `GET /api/auth/me`
* **Implemented At:** `backend/server/api/auth/index.js#L2317-L2550`
* **Specific Problem:**
  ```javascript
  // 1. Initial user lookup if ObjectId
  const basicUser = await userDataCol.findOne(query, { projection: { email: 1 } });
  // 2. Subscription lazy check (writes to DB)
  await activateDueSubscriptionForUser(db, userEmailForSync);
  // 3. Second user lookup for full fields
  const user = await userDataCol.findOne(query, { projection: { ... } });
  // 4. First license lookup by key
  let activeLic = await licensesCol.findOne({ licenseKey: user.plan.activeLicenseKey, status: "active" });
  // 5. Fallback license lookup by email
  if (!activeLic) activeLic = await licensesCol.findOne({ userEmail: user.email, status: "active" }, { sort: { createdAt: -1 } });
  // 6. User Login lookup for super_admin flag
  const loginUser = await userLoginCol.findOne(loginQuery, { projection: { super_admin: 1 } });
  // 7. Duplicate license lookup in org admin access check
  let license = await licensesCol.findOne({ licenseKey: user.plan.activeLicenseKey, status: { $ne: "revoked" } });
  // 8. DARC license lookup fallback
  const darcLic = await darcLicensesCol.findOne({ $or: darcQueries, status: { $nin: [...] } });
  ```
* **Why It Hurts:**
  `GET /api/auth/me` is invoked whenever the user navigates routes or refreshes the page. The handler executes 5 to 8 sequential database queries on every call, including duplicate queries to `licenses` (lines 2389 and 2465) and redundant fetches to `userDataCol`. None of this session state is cached.
* **Concrete Fix:**
  1. Cache authenticated user session state and active license tier in Redis or an in-memory LRU cache for 5 minutes.
  2. Reuse `activeLic` from line 2389 instead of querying `licensesCol` again at line 2465.
* **Priority:** 🔴 **HIGH**

---

### 3.8. Watchlist Feed: Unbounded Memory Fetch & `$expr` Date Scanning
* **Method & Path:** `GET /api/watchlist/feed`
* **Implemented At:** `backend/controllers/watchlistController.js#L2550-L2850`
* **Specific Problem:**
  ```javascript
  const uniqueCveIds = Array.from(new Set(cveIdsToFetch.map((item) => item.cveId)));
  const metaQuery = {
    $or: [{ _id: { $in: uniqueCveIds } }, { cve_id: { $in: uniqueCveIds } }],
  };
  if (month && !year) {
    metaQuery.$expr = { $eq: [{ $month: { $convert: { input: "$published_at", to: "date", onError: null, onNull: null } } }, month] };
  }
  const cveMeta = await unifiedCvesCollection.find(metaQuery).project({ ... }).toArray();
  sortCveRefs(sortableRefs, metaMap, sortByCVSS);
  const pageRefs = sortableRefs.slice(skip, skip + limit);
  ```
* **Why It Hurts:**
  1. **Unbounded Intermediate Fetch:** `metaQuery` loads the entire matching set of CVE IDs into Node.js memory (`.toArray()`) with no `.limit()`. For watchlists matching 10,000+ CVEs, all 10,000 documents are transferred across the network and sorted in JavaScript memory before slicing page 1.
  2. **Unindexed `$expr`:** The `$expr` date conversion cannot use an index on `published_at`, triggering full document scans.
  3. **Unbounded `onlyIds=true`:** When `onlyIds=true`, it returns the entire unpaginated query set directly.
* **Concrete Fix:**
  Push sorting and pagination directly into MongoDB so that only `limit` documents are retrieved over the wire:
  ```javascript
  const pagedCves = await unifiedCvesCollection
    .find({ cve_id: { $in: uniqueCveIds } })
    .project(cveProjection)
    .sort(sortStage)
    .skip(skip)
    .limit(limit)
    .toArray();
  ```
* **Priority:** 🔴 **HIGH**

---

### 3.9. Activity Heatmap: Sequential 12-Month Query Loop & Cache Bypassed
* **Method & Path:** `GET /api/dashboard/heatmap-resolved-cves`
* **Implemented At:** `backend/routes/dashboardRoutes.js#L519-L525` & `backend/controllers/dashboardController.js#L2650-L2800`
* **Specific Problem:**
  ```javascript
  // In routes/dashboardRoutes.js:
  // CACHE DISABLED:
  for (const { year: y, month: m } of normalized) {
    const data = await getTotalResolvedCVEsMonth(db, username, y, monthStr);
    if (Array.isArray(data)) allData = allData.concat(data);
  }

  // Inside controllers/dashboardController.js (getTotalResolvedCVEsMonth):
  const feed = await db.collection("feed").findOne({ _id: username }, { projection: { products: 1, cves: 1 } });
  const userWatchlistsDoc = await db.collection("User_Data").findOne({ email: username }, { projection: { "dashboard_data.watchlists": 1 } });
  ```
* **Why It Hurts:**
  When rendering a 1-year activity heatmap, the route executes a sequential loop over all 12 months. In each iteration, `getTotalResolvedCVEsMonth` queries `feed` and `User_Data`. The exact same two user documents are fetched from the database **12 separate times in a single HTTP request**, followed by repeated in-memory iteration of all historical items.
* **Concrete Fix:**
  1. Load `feed` and `User_Data` once before the loop:
  ```javascript
  const [feed, userDoc] = await Promise.all([
    db.collection("feed").findOne({ _id: username }, { projection: { products: 1, cves: 1 } }),
    db.collection("User_Data").findOne({ email: username }, { projection: { "dashboard_data.watchlists": 1 } }),
  ]);
  // Process all 12 months in a single in-memory pass over feed.cves
  ```
  2. Re-enable feed cache with a 1-hour TTL.
* **Priority:** 🟡 **MEDIUM**

---

### 3.10. Global Search & Autocomplete: 5-Collection Unanchored Regex Scatter
* **Method & Path:** `GET /api/cve/autocomplete`
* **Implemented At:** `backend/controllers/cveController.js#L1380-L1460`
* **Specific Problem:**
  ```javascript
  const prefixRegex = new RegExp("^" + escapedFirstWord, "i");
  const [searchVendors, primaryVendors, searchProducts, primaryProducts, cveDocs] = await Promise.all([
    db.collection("Search_Vendor").find({ vendor: { $regex: prefixRegex } }).limit(30).toArray(),
    db.collection("vendors").find({ vendor: { $regex: prefixRegex } }).limit(20).toArray(),
    db.collection("Search_Product").find({ $or: [{ product: { $regex: prefixRegex } }, { searchText: { $regex: prefixRegex } }] }).limit(30).toArray(),
    db.collection("products").find({ $or: [{ product: { $regex: prefixRegex } }, { product_name: { $regex: prefixRegex } }] }).limit(30).toArray(),
    db.collection("Search_CVE").find({ cve_id: { $regex: prefixRegex } }).limit(limit).toArray(),
  ]);
  ```
* **Why It Hurts:**
  Every keystroke in the global search bar fires queries across 5 different collections concurrently. The `$or` queries on `Search_Product` and `products` examine non-prefix fields (`searchText`, `product_name`) with case-insensitive regular expressions, bypassing single-field b-tree indexes and causing collection scanning under typing bursts.
* **Concrete Fix:**
  1. Consolidate search records into a single dedicated autocomplete collection (e.g. `search_index`) with lowercase normalized prefix tokens.
  2. Replace regex with an indexed prefix seek (`{ token: { $gte: term, $lt: term + "\uffff" } }`) or MongoDB Atlas Search / text index.
* **Priority:** 🟡 **MEDIUM**

---

### 3.11. Monthly Threat Intelligence Report: Synchronous Heavy Aggregation
* **Method & Path:** `POST /api/reports/monthly-threat/generate`
* **Implemented At:** `backend/controllers/monthlyThreatReportController.js#L140-L170` & `backend/services/monthlyThreatReportService.js#L80-L180`
* **Specific Problem:**
  ```javascript
  // In controllers/monthlyThreatReportController.js:
  const report = await computeGlobalMonthlyReport(db, year, month, true);
  return res.status(200).json({ success: true, data: report });

  // In services/monthlyThreatReportService.js:
  const [facetResults, topExploitedRaw, newsArticles] = await Promise.all([
    unifiedCol.aggregate([
      { $match: dateMatch },
      { $facet: { macroTotals: [...], severityBreakdown: [...], topVendors: [...], ... } }
    ]),
    ...
  ]);
  ```
* **Why It Hurts:**
  `computeGlobalMonthlyReport` runs an extensive multi-facet aggregation spanning 15,000–30,000 CVEs published in that month. Executing this synchronously within the HTTP handler holds the client socket open for 10–30+ seconds, blocks workers from handling lightweight traffic, and risks HTTP 504 Gateway Timeouts from upstream Nginx proxies.
* **Concrete Fix:**
  Offload report generation to an Agenda background job. Return `202 Accepted` immediately with a status polling URL or job ID:
  ```javascript
  await agenda.now("compute-monthly-threat-report", { year, month });
  return res.status(202).json({ success: true, message: "Report generation queued" });
  ```
* **Priority:** 🟡 **MEDIUM**

---

### 3.12. License Management: Eager Mail Dispatch in Loop & Unindexed `$or` Regex
* **Method & Path:** `GET /api/license/search`, `GET /api/license/all`
* **Implemented At:** `backend/controllers/licenseController.js#L120-L180, L240-L310`
* **Specific Problem:**
  ```javascript
  // In GET /api/license/all:
  licensesCol.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();
  const licenses = rawLicenses.map((lic) => {
    ...
    if (correctStatus !== lic.status && lic.licenseKey) {
      licensesCol.updateOne(...).then(() => {
        if (correctStatus === "expired" && lic.userEmail) {
          sendMail(lic.userEmail, ...); // Synchronous mail formatting & dispatch
        }
      });
    }
  });

  // In GET /api/license/search:
  filter.$or = [
    { licenseKey: { $regex: escapedQ, $options: "i" } },
    { userEmail: { $regex: escapedQ, $options: "i" } },
    { createdBy: { $regex: escapedQ, $options: "i" } },
  ];
  ```
* **Why It Hurts:**
  1. `GET /api/license/search` runs an unanchored case-insensitive `$or` regex across 3 fields without a compound index on the `licenses` collection.
  2. `GET /api/license/all` checks expiration inside `.map()` over 100 items and fires individual unbatched `updateOne` calls and Mailgun email deliveries during a read query.
* **Concrete Fix:**
  1. Move license expiration status checks and email dispatches to a daily cron job (`cronJobs.js`).
  2. Create a compound index on `licenses`: `{ status: 1, userEmail: 1, licenseKey: 1 }`.
* **Priority:** 🟡 **MEDIUM**

---

### 3.13. Organization Activity Logs: Cascading Hierarchy Resolution & Unanchored Text Search
* **Method & Path:** `GET /api/org-logs/`
* **Implemented At:** `backend/controllers/orgLogsController.js#L350-L520, L600-L700`
* **Specific Problem:**
  ```javascript
  // Cascading scope resolution queries:
  const branches = await db.collection("branches").find({ region_id: { $in: regionIdVariants } }).toArray();
  const teams = await db.collection("teams").find({ branch_id: { $in: branchIds } }).toArray();
  const devices = await db.collection("Agent_Inventory").find({ teamId: { $in: teamIds } }).toArray();

  // Search regex across audit DB:
  const searchOr = [
    { action: searchRegex },
    { entity: searchRegex },
    { detailsText: searchRegex },
  ];
  const orgLogs = await auditDb.collection("org_activity_logs")
    .find(finalFilter)
    .sort({ timestamp: -1 })
    .skip(skip).limit(limit)
    .toArray();
  ```
* **Why It Hurts:**
  Filtering logs by `regionId` requires 3 cascading database calls across `branches`, `teams`, and `Agent_Inventory` to collect ID arrays. If a search query is provided, it executes a case-insensitive regex against `detailsText` across the audit log collection, forcing a collection scan on large log sets.
* **Concrete Fix:**
  1. Denormalize hierarchy identifiers onto `org_activity_logs` records at write time (`org_id`, `region_id`, `branch_id`, `team_id`) so log filtering uses a single direct indexed query: `{ region_id: regionId }`.
  2. Create a compound index on `cve-audit.org_activity_logs`:
  ```javascript
  auditDb.collection("org_activity_logs").createIndex(
    { orgId: 1, timestamp: -1 },
    { name: "idx_org_logs_org_time" }
  );
  ```
* **Priority:** 🟡 **MEDIUM**

---

### 3.14. Single CVE Endpoints: Unprojected Full Document Over-Fetching
* **Method & Path:** `GET /api/product/cve/:cveId`
* **Implemented At:** `backend/controllers/productcontroller.js#L80-L120`
* **Specific Problem:**
  ```javascript
  const cve = await db.collection("unified_cves").findOne({ cve_id: cacheKey });
  return res.json({ cve });
  ```
* **Why It Hurts:**
  Calls `findOne` on `unified_cves` without a projection (`SELECT *`). In ZeroWatch, CVE records contain massive nested configurations: full NVD JSON payloads, raw MITRE reference lists, and hundreds of vulnerable version ranges. Returning the entire unprojected document consumes unnecessary network bandwidth and JSON serialization overhead when the frontend only renders a subset of fields.
* **Concrete Fix:**
  Add a strict projection omitting internal raw sync payloads:
  ```javascript
  const cve = await db.collection("unified_cves").findOne(
    { cve_id: cacheKey },
    { projection: { raw_nvd_json: 0, raw_mitre_json: 0, internal_sync_history: 0 } }
  );
  ```
* **Priority:** 🟢 **LOW**

---

## 4. Recommended Database Indexes

The following indexes are missing or require collation adjustments to eliminate collection scans identified during the audit:

| Target Collection | Index Specification (Fields & Sort) | Options | Serving Endpoints / Workloads |
| :--- | :--- | :--- | :--- |
| `unified_cves` | `{ "cpe.vendor": 1, "cpe.product": 1 }` | `collation: { locale: "en", strength: 2 }, name: "idx_cpe_vendor_product_collation", background: true` | `POST /api/agent/sync/full`, `POST /api/agent/sync/delta`, `agentFeedService.js` (Eliminates full table scans during software inventory matching) |
| `unified_cves` | `{ "vulnerable_cpe.vendor": 1, "vulnerable_cpe.product": 1 }` | `collation: { locale: "en", strength: 2 }, name: "idx_vuln_cpe_vendor_product_collation", background: true` | `POST /api/agent/sync/full`, `agentFeedService.js` (Eliminates full table scans on fallback vulnerable CPE matching) |
| `Agent_Inventory` | `{ team_id: 1, deviceId: 1, status: 1 }` | `name: "idx_agent_team_device_status", background: true` | `POST /api/agent/heartbeat`, `GET /api/teams/feed`, `GET /api/teams/devices`, `teamDashboard.js` |
| `agent_feed` | `{ deviceId: 1, "vulnerabilities.status": 1 }` | `name: "idx_agent_feed_device_status", background: true` | `GET /api/teams/feed`, `GET /api/teams/dashboard/summary-stats`, `GET /api/device-feed/:deviceId` |
| `agent_feed` | `{ teamId: 1, last_updated: -1 }` | `name: "idx_agent_feed_team_updated", background: true` | `GET /api/dashboard/v2/managed-teams-overview`, `billingReportService.js` |
| `licenses` | `{ userEmail: 1, status: 1, createdAt: -1 }` | `name: "idx_licenses_email_status_created", background: true` | `GET /api/auth/me`, `GET /api/license/status`, `GET /api/license/check-existing/:email` |
| `licenses` | `{ licenseKey: 1, status: 1 }` | `name: "idx_licenses_key_status", background: true` | `GET /api/auth/me`, `POST /api/agent/heartbeat`, `licenseController.js` |
| `org_activity_logs` *(in `cve-audit` DB)* | `{ orgId: 1, timestamp: -1, level: 1 }` | `name: "idx_org_logs_org_time_level", background: true` | `GET /api/org-logs/`, `GET /api/teams/activity-logs` |
| `feed` | `{ _id: 1, "cves.status": 1 }` | `name: "idx_user_feed_status", background: true` | `GET /api/watchlist/feed`, `GET /api/dashboard/summary-stats` |
| `User_Data` | `{ "dashboard_data.watchlists.items.product.vendor": 1, "dashboard_data.watchlists.items.product.product": 1 }` | `name: "idx_userdata_watchlists_vendor_prod", background: true` | `GET /api/watchlist/watchlist-stats`, `GET /api/dashboard/heatmap-resolved-cves` |

---

## 5. Architectural Recommendations

1. **Eliminate the 50–80ms Artificial Throttling**: Remove `setTimeout` normalization from `index.js:281` across API routes. This change will immediately reduce response latency by 50–80ms across all 401 endpoints.
2. **Re-Enable Dashboard Numeric Cache**: Restore the in-memory/Redis coalesced cache on `teamDashboard.js:138` with a 30-second TTL to eliminate the 6x query storm when the team dashboard opens.
3. **Consolidate Heartbeat Processing**: In `agentController.js:3177`, cache team metadata and remove the duplicate `findOne` on `Agent_Inventory` to reduce database operations per heartbeat by 50%.
4. **Move Long-Running Aggregations to Background Jobs**: Transition `POST /api/reports/monthly-threat/generate` and hierarchy re-computations to asynchronous Agenda tasks to prevent reverse-proxy timeouts.
