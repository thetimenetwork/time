// Compares the pinned main module against every returned Go OSV entry using
// the official Go semantic-version implementation and actual go-list packages.
package main

import (
 "bufio"
 "encoding/json"
 "fmt"
 "os"
 "strings"
 "golang.org/x/mod/semver"
)
type Event map[string]string
type Range struct { Type string `json:"type"`; Events []Event `json:"events"` }
type Import struct { Path string `json:"path"` }
type Affected struct { Package struct{Name string `json:"name"`} `json:"package"`; Ranges []Range `json:"ranges"`; Versions []string `json:"versions"`; Ecosystem struct {Imports []Import `json:"imports"`} `json:"ecosystem_specific"` }
type Advisory struct { ID string `json:"id"`; Summary string `json:"summary"`; Affected []Affected `json:"affected"` }
func must(err error){if err!=nil{panic(err)}}
func version(text string)string{if text=="0"{return "v0.0.0"};if !strings.HasPrefix(text,"v"){text="v"+text};if !semver.IsValid(text){panic("invalid advisory version: "+text)};return text}
func matches(affected Affected,target string)bool{
 result:=false
 for _,item:=range affected.Versions{if semver.Compare(version(item),target)==0{result=true}}
 for _,item:=range affected.Ranges{if item.Type!="SEMVER"{panic("unsupported OSV range type")};inside:=false;for _,event:=range item.Events{if len(event)!=1{panic("noncanonical OSV range event")};for kind,text:=range event{comparison:=semver.Compare(target,version(text));switch kind{case "introduced":if comparison>=0{inside=true};case "fixed","limit":if comparison>=0{inside=false};case "last_affected":if comparison>0{inside=false};default:panic("unknown OSV event")}}};result=result||inside}
 return result
}
func main(){
 if len(os.Args)!=3{panic("report and package graph required")};raw,err:=os.ReadFile(os.Args[1]);must(err);var report struct{Advisories []Advisory `json:"advisories"`};must(json.Unmarshal(raw,&report));file,err:=os.Open(os.Args[2]);must(err);defer file.Close();packages:=map[string]bool{};scanner:=bufio.NewScanner(file);for scanner.Scan(){packages[scanner.Text()]=true};must(scanner.Err());if !packages["github.com/cometbft/cometbft/blocksync"]{panic("expected pinned v0.38 blocksync package missing")}
 reviewed:=[]map[string]any{};seen:=map[string]bool{};applicable:=[]string{};const target="v0.38.26";const module="github.com/cometbft/cometbft"
 for _,advisory:=range report.Advisories{if seen[advisory.ID]{continue};seen[advisory.ID]=true;entries:=[]map[string]any{};hit:=false;for _,affected:=range advisory.Affected{if affected.Package.Name!=module{continue};versionMatch:=matches(affected,target);imports:=[]map[string]any{};packageMatch:=len(affected.Ecosystem.Imports)==0;for _,item:=range affected.Ecosystem.Imports{present:=packages[item.Path];imports=append(imports,map[string]any{"path":item.Path,"present_in_exact_build_graph":present});packageMatch=packageMatch||present};hit=hit||(versionMatch&&packageMatch);entries=append(entries,map[string]any{"ranges":affected.Ranges,"version_matches":versionMatch,"imports":imports,"package_matches":packageMatch})};if len(entries)>0{reviewed=append(reviewed,map[string]any{"id":advisory.ID,"summary":advisory.Summary,"entries":entries,"potentially_applicable":hit});if hit{applicable=append(applicable,advisory.ID)}}}
 if len(reviewed)==0{panic("no Comet advisories present; cannot claim reviewed")};status:="NO_KNOWN_MAIN_MODULE_VERSION_PACKAGE_MATCHES";if len(applicable)>0{status="POTENTIALLY_APPLICABLE_MAIN_MODULE_ADVISORIES"};output:=map[string]any{"status":status,"module":module,"version":target,"version_implementation":"golang.org/x/mod/semver v0.42.0 (same checksum-pinned dependency as govulncheck v1.9.0)","package_count":len(packages),"reviewed":reviewed,"applicable":applicable,"public_funds_allowed":false,"limitations":[]string{"Package/version presence is not a callgraph reachability analysis or security proof.","This supplements the unversioned custom main-module gap in binary scanning; no advisory ID is suppressed."}};bytes,err:=json.MarshalIndent(output,"","  ");must(err);fmt.Println(string(bytes))
}
