#!/usr/bin/env python3
"""No-network tests for mapping a pre-verified formal Windows Release to Catalog v2."""
import copy
import unittest
from scripts.verified_release_record import INTAKE_ALLOWED, Denied, majors, tag_for, map_verified_release, seed_verified_first_release

REFS={
 "pg_bigm":("v1.2-20250903","1.2"),
 "pg_cron":("v1.6.8","1.6.8"),
 "set_user":("REL4_2_0","4.2.0"),
 "pg_repack":("ver_1.5.3","1.5.3"),
 "pg_ivm":("v1.16","1.16"),
 "pg_qualstats":("2.1.4","2.1.4"),
 "plpgsql_check":("v2.10.14","2.10.14"),
 "hypopg":("1.4.3","1.4.3"),
 "wal2json":("wal2json_2_7","2.7"),
 "pg_partman":("v5.5.0","5.5.0"),
 "pg_stat_monitor":("2.4.0","2.4.0"),
 "orafce":("VERSION_4_16_13","4.16.13"),
 "pgtap":("v1.3.4","1.3.4"),
 "pg_variables":("v1.2.1","1.2.1"),
 "pg_store_plans":("1.10","1.10")
}
PER={
 "pgaudit":{14:("1.6.3","1.6.3"),15:("1.7.1","1.7.1"),16:("16.1","16.1"),17:("17.1","17.1"),18:("18.0","18.0")},
 "pg_hint_plan":{14:("REL14_1_4_4","1.4.4"),15:("REL15_1_5_3","1.5.3"),16:("REL16_1_6_2","1.6.2"),17:("REL17_1_7_1","1.7.1"),18:("REL18_1_8_0","1.8.0")}
}
def fixture(name, revision="3"):
    repo="pgextwin/"+name
    up={"repository":INTAKE_ALLOWED[name]}
    if name in REFS:
        ref,vers=REFS[name]
        up.update(ref=ref,version=vers,commit="a"*40)
    else:
        up["perPostgresql"]={str(m):{"ref":ref,"version":v,"commit":"b"*40}
                              for m,(ref,v) in PER[name].items()}
    ext={"name":name,"upstream":up,"postgresql":{"majors":[14,15,16,17,18]}}
    tag=tag_for(ext,revision)
    base={"schemaVersion":2,"name":name,"repository":repo,
          "upstream":{"repository":INTAKE_ALLOWED[name],"version":"historical"},
          "postgresql":{str(m):{} for m in range(14,19)},
          "runtime":{"requirements":{}},"capabilities":{},"capabilitiesSource":{}}
    rel={"tag_name":tag,"draft":False,"prerelease":False,
         "html_url":f"https://github.com/{repo}/releases/tag/{tag}",
         "published_at":"2026-10-11T12:00:00Z",
         "target_commitish":"c"*40}
    tc={"contractVersion":2,"extension":name,
        "runtimeRequirements":{"preload":"optional"},
        "coverage":{"upgrade":"not-covered"},
        "functionalScenarios":[{"id":"smoke","description":"smoke","evidence":["sql-result"]}]}
    download=f"https://github.com/{repo}/releases/download/{tag}/"
    assets={"SHA256SUMS.txt":{"name":"SHA256SUMS.txt","state":"uploaded",
                             "browser_download_url":download+"SHA256SUMS.txt","digest":"sha256:"+"e"*64}}
    sums={"SHA256SUMS.txt":"e"*64}
    for m in range(14,19):
        ref=up["perPostgresql"][str(m)]["ref"] if name in PER else up["ref"]
        stem=name+"-"+ref+"-pg"+str(m)+"-windows-x64"
        for suffix in (".zip",".spdx.json",".vulnerabilities.json"):
            filename=stem+suffix
            sums[filename]="f"*64
            assets[filename]={"name":filename,"state":"uploaded","browser_download_url":download+filename,
                              "digest":"sha256:"+"f"*64}
    return base,rel,ext,tc,assets,sums

def licenses(name, required):
    url = f"https://github.com/pgextwin/{name}/blob/{'c'*40}/LICENSE"
    return {str(major): {"name": "PostgreSQL", "evidenceUrls": [url]} for major in required}


def mapped(name, parts=None, required=None, **kwargs):
    parts=parts if parts is not None else fixture(name)
    base,rel,ext,tc,assets,sums=parts
    required = required if required is not None else [14,15,16,17,18]
    return map_verified_release(base,rel,ext,tc,assets,sums,"c"*40,required,
                                licenses_by_major=licenses(name, required), **kwargs)

class RecordTests(unittest.TestCase):
    def test_existing_seventeen_source_and_asset_naming_rules(self):
        # Immutable historical fixtures are a mandatory subset, not a ceiling
        # on protected future first-Release registrations.
        self.assertTrue((set(REFS) | set(PER)).issubset(INTAKE_ALLOWED))
        for name in sorted(set(REFS) | set(PER)):
            with self.subTest(name=name):
                original=fixture(name)
                after=mapped(name,original)
                self.assertEqual(after["latest"]["releaseTag"],original[1]["tag_name"])
                self.assertEqual(after["capabilitiesSource"]["commit"],"c"*40)
                self.assertEqual(len(after["postgresql"]),5)
                self.assertEqual(after["postgresql"]["14"]["evidence"]["sbom"]["sha256"],"f"*64)
                self.assertEqual(original[0]["upstream"]["version"],"historical")
                for major in range(14,19):
                    ref=(original[2]["upstream"]["perPostgresql"][str(major)]["ref"]
                         if name in PER else original[2]["upstream"]["ref"])
                    self.assertIn("-"+ref+"-pg"+str(major)+"-",after["postgresql"][str(major)]["asset"])
                self.assertEqual(after["capabilities"]["testContractVersion"],2)

    def test_rollover_preserves_prior_approved_rows_and_replaces_same_version(self):
        current = mapped("hypopg")
        prior_license = current["releaseInventory"]["current"]["licensesByMajor"]["15"]
        old_tag = "v1.4.2-windows.1"
        current["latest"]["releaseTag"] = old_tag
        current["releaseInventory"]["current"]["releaseTag"] = old_tag
        current["upstream"]["version"] = "1.4.2"

        for pg in current["postgresql"].values():
            pg["downloadUrl"] = pg["downloadUrl"].replace("v1.4.3-windows.3", old_tag)
        repo = "pgextwin/hypopg"
        assets = [{"name": pg["asset"], "id": int(major), "state": "uploaded",
                   "digest": "sha256:" + pg["sha256"], "browser_download_url": pg["downloadUrl"]}
                  for major, pg in current["postgresql"].items()]
        assets.append({"name": "SHA256SUMS.txt", "id": 100, "state": "uploaded",
                       "browser_download_url": f"https://github.com/{repo}/releases/download/{old_tag}/SHA256SUMS.txt"})
        previous = {"tag_name": old_tag, "id": 101, "draft": False,
                    "published_at": current["latest"]["publishedAt"], "assets": assets}
        parts = (current, *fixture("hypopg")[1:])
        switched = mapped("hypopg", parts, load_previous=lambda tag: ("a"*40, previous))
        history, = switched["releaseInventory"]["history"]
        self.assertEqual(history["releaseId"], 101)
        self.assertEqual(history["admission"], {"catalogCommit": "a"*40})
        row = next(row for row in history["packages"] if row["pgMajor"] == "15")
        self.assertEqual((row["version"], row["assetId"], row["license"]), ("1.4.2", 15, prior_license))

        revision = fixture("hypopg", revision="4")
        replaced = mapped("hypopg", (switched, *revision[1:]))
        self.assertEqual(replaced["releaseInventory"]["current"]["releaseTag"], "v1.4.3-windows.4")
        self.assertEqual(replaced["releaseInventory"]["history"], [history])
        stale_duplicate = {**history, "packages": [{**row, "version": "1.4.3"}]}
        switched["releaseInventory"]["history"].append(stale_duplicate)
        deduped = mapped("hypopg", (switched, *revision[1:]))
        self.assertEqual(deduped["releaseInventory"]["history"], [history])

    def test_rollover_rejects_losing_established_license_evidence(self):
        name = "pg_repack"
        current = mapped(name)
        current["releaseInventory"]["current"]["licensesByMajor"]["15"]["evidenceUrls"].append(
            f"https://github.com/postgres/postgres/blob/{'d' * 40}/COPYRIGHT")
        revision = fixture(name, revision="4")
        with self.assertRaisesRegex(Denied, "established license evidence missing for PG15"):
            mapped(name, (current, *revision[1:]))

    def test_rollover_rejects_available_old_zip_missing_license_evidence(self):
        current = mapped("hypopg")
        current["upstream"]["perPostgresql"] = {"16": {"version": "1.4.2"}}
        del current["releaseInventory"]["current"]["licensesByMajor"]["16"]
        revision = fixture("hypopg", revision="4")
        with self.assertRaisesRegex(Denied, "previous Release v1.4.3-windows.3 lacks license evidence for PG16"):
            mapped("hypopg", (current, *revision[1:]))

    def test_first_release_seed_requires_exact_third_wave_identity(self):
        for name in ("pgtap", "pg_variables", "pg_store_plans"):
            with self.subTest(name=name):
                base, release, manifest, contract, assets, sums = fixture(name)
                if name == "pg_store_plans":
                    contract["runtimeRequirements"]["preload"] = "shared"
                seed = seed_verified_first_release(manifest, contract)
                self.assertEqual(seed["latest"], {})
                self.assertEqual(seed["postgresql"], {})
                self.assertEqual(seed["repository"], "pgextwin/" + name)
                self.assertEqual(seed["upstream"]["repository"], INTAKE_ALLOWED[name])
                result = map_verified_release(
                    seed, release, manifest, contract, assets, sums, "c"*40,
                    [14, 15, 16, 17, 18],
                    licenses_by_major=licenses(name, [14, 15, 16, 17, 18]))
                self.assertEqual(len(result["postgresql"]), 5)
                self.assertEqual(result["latest"]["releaseTag"], release["tag_name"])
                self.assertEqual(result["runtime"]["sharedPreloadLibraries"],
                                 ["pg_store_plans"] if name == "pg_store_plans" else [])
        base, release, manifest, contract, assets, sums = fixture("orafce")
        with self.assertRaises(Denied):
            seed_verified_first_release(manifest, contract)
        base, release, manifest, contract, assets, sums = fixture("pg_variables")
        manifest["upstream"]["commit"] = "unverified"
        with self.assertRaises(Denied):
            seed_verified_first_release(manifest, contract)

    def test_stale_pg14_is_preserved_when_not_maintained(self):
        parts=fixture("wal2json")
        parts[0]["postgresql"]["14"]={"available":True,"asset":"historical-pg14.zip"}
        for name in list(parts[4]):
            if "-pg14-" in name:
                del parts[4][name]
                del parts[5][name]
        out=mapped("wal2json",parts,required=[15,16,17,18])
        # PG14 is EOL: the major is preserved as an explicit unavailable
        # marker, never carried forward as available under a Release tag
        # that has no PG14 assets.
        self.assertEqual(out["postgresql"]["14"],{"available":False})
        self.assertEqual(out["postgresql"]["15"]["available"],True)

    def test_pg14_rollover_marks_unavailable_for_pg19_release(self):
        # wal2json-shaped rollover: the existing record carries a full
        # PG14 entry bound to the old tag; the new Release covers 15-19.
        parts=fixture("wal2json")
        parts[0]["postgresql"]["14"]={
            "available":True,"asset":"wal2json-wal2json_2_7-pg14-windows-x64.zip",
            "downloadUrl":"https://github.com/pgextwin/wal2json/releases/download/v2.7-windows.1/wal2json-wal2json_2_7-pg14-windows-x64.zip",
            "sha256":"f"*64,"evidence":{}}
        for name in list(parts[4]):
            if "-pg14-" in name:
                del parts[4][name]
                del parts[5][name]
        for m in (19,):
            ref=parts[2]["upstream"]["ref"]
            stem="wal2json-"+ref+"-pg"+str(m)+"-windows-x64"
            for suffix in (".zip",".spdx.json",".vulnerabilities.json"):
                fn=stem+suffix
                parts[5][fn]="f"*64
                parts[4][fn]={"name":fn,"state":"uploaded","digest":"sha256:"+"f"*64,
                              "browser_download_url":f"https://github.com/pgextwin/wal2json/releases/download/{parts[1]['tag_name']}/{fn}"}
        parts[2]["postgresql"]["majors"]=[14,15,16,17,18,19]
        out=mapped("wal2json",parts,required=[15,16,17,18,19])
        self.assertEqual(out["postgresql"]["14"],{"available":False})
        self.assertEqual(out["postgresql"]["19"]["available"],True)

    def test_tampered_release_and_assets_are_rejected(self):
        mutations=(
            lambda p:p[1].update(draft=True),
            lambda p:p[1].update(target_commitish="0"*40),
            lambda p:p[1].update(tag_name="v99.9-windows.1"),
            lambda p:p[1].update(html_url="https://example.invalid/release"),
            lambda p:p[2]["upstream"].update(repository="attacker/wal2json"),
            lambda p:p[2]["upstream"].update(commit=None),
            lambda p:p[4].pop(next(x for x in p[4] if x.endswith(".zip"))),
            lambda p:p[5].pop(next(iter(p[5]))),
            lambda p:next(a for a in p[4].values() if a["name"].endswith(".zip")).update(digest="sha256:"+"0"*64),
            lambda p:next(a for a in p[4].values() if a["name"].endswith(".zip")).update(browser_download_url="https://example.invalid/file.zip"),
            lambda p:p[4]["SHA256SUMS.txt"].update(digest="sha256:"+"0"*64),
            lambda p:p[3].update(extension="other"),
        )
        for index,mut in enumerate(mutations):
            with self.subTest(index=index):
                f=fixture("wal2json")
                mut(f)
                with self.assertRaises(Denied):
                    mapped("wal2json",f)

    def test_per_major_missing_pin_is_rejected(self):
        f=fixture("pgaudit")
        f[2]["upstream"]["perPostgresql"]["16"].pop("commit")
        with self.assertRaises(Denied):
            mapped("pgaudit",f)

    def test_pg14_missing_from_release_is_not_implicitly_accepted(self):
        f=fixture("hypopg")
        with self.assertRaises(Denied):
            mapped("hypopg",f,required=[14,15,16,16,18])

class MajorsCap(unittest.TestCase):
    def test_pg19_accepted_pg20_denied(self):
        self.assertEqual(majors({"postgresql": {"majors": [15, 16, 17, 18, 19]}}),
                         [15, 16, 17, 18, 19])
        self.assertEqual(majors({"postgresql": {"minMajor": 15, "maxMajor": 19}}),
                         [15, 16, 17, 18, 19])
        with self.assertRaises(Denied):
            majors({"postgresql": {"majors": [15, 16, 17, 18, 19, 20]}})


if __name__=="__main__":
    unittest.main()
