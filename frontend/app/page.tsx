"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, Bot, Bug, Check, ChevronRight, Circle, Clock3, Download,
  FileCode2, FileSearch, Fingerprint, Gauge, Inbox, Link2, LockKeyhole,
  Mail, Menu, Network, Play, RefreshCw, Search, ServerCog, Settings, ShieldAlert,
  ShieldCheck, Sparkles, TriangleAlert, X, XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

type Module = "Inbox" | "Email Analysis" | "Malware Analyser" | "Risk Assessment" | "Reports";
type MailRisk = "critical" | "high" | "medium" | "safe";
type CheckState = "pass" | "fail" | "warn";
type ScanState = "idle" | "loading" | "complete" | "error";

type AnalysisCheck = {
  name:string; group:string; state:CheckState; score:number; result:string; recommendation:string;
};

type MailItem = {
  id: string; sender: string; email: string; subject: string; preview: string; time: string;
  score: number; risk: MailRisk; unread?: boolean; attachment?: string; initials: string;
  source?: "demo" | "gmail"; scanned?: boolean; gmailId?: string; scannedAt?: string;
};

type GmailMessage = {
  id: string; threadId?: string; from: string; to: string; subject: string; date: string;
  snippet: string; labels?: string[];
  scan?: {status:"pending"|"complete"; scanned_at?:string; score?:number; verdict?:string; severity?:MailRisk};
};

type ConnectionState = "idle" | "connecting" | "connected" | "error";

const GMAIL_CONNECTOR_BASE = "http://127.0.0.1:8000";
const GMAIL_CONNECTOR_URL = `${GMAIL_CONNECTOR_BASE}/api/messages`;

const demoMails: MailItem[] = [
  { id:"PG-0421", sender:"Microsoft Security", email:"account-alert@microsoft-secure-login.co", subject:"URGENT: Account suspension notice", preview:"Verify your password immediately to retain access…", time:"10:42 AM", score:94, risk:"critical", unread:true, attachment:"Security_Update.pdf.exe", initials:"MS" },
  { id:"PG-0420", sender:"Accounts Payable", email:"billing@vendor-payments.net", subject:"Invoice #3482 awaiting payment", preview:"Please process the attached invoice before EOD…", time:"9:18 AM", score:68, risk:"high", unread:true, attachment:"Invoice_3482.xlsm", initials:"AP" },
  { id:"PG-0419", sender:"People Excellence", email:"people@sisainfosec.com", subject:"September policy communication", preview:"Please find the updated policy document…", time:"8:51 AM", score:7, risk:"safe", attachment:"Policy_Update.pdf", initials:"PE" },
  { id:"PG-0418", sender:"Dharshan", email:"dharshan@sisainfosec.com", subject:"Leadership review — Friday", preview:"Sharing the discussion points for our review…", time:"Yesterday", score:3, risk:"safe", initials:"DS" },
  { id:"PG-0417", sender:"Dropbox Files", email:"share@dropb0x-documents.com", subject:"A confidential file was shared", preview:"Open the protected document using this link…", time:"Yesterday", score:81, risk:"critical", unread:true, initials:"DB" },
  { id:"PG-0416", sender:"Talent Acquisition", email:"careers@sisainfosec.com", subject:"Candidate profiles for SOC L2", preview:"Attaching shortlisted profiles for review…", time:"13 Sep", score:5, risk:"safe", attachment:"Profiles.zip", initials:"TA" },
];

const demoChecks: AnalysisCheck[] = [
  {name:"SPF Verification",group:"Authentication",state:"fail",score:12,result:"Sender IP is not authorised by the claimed domain's SPF policy.",recommendation:"Treat the sender identity as untrusted."},
  {name:"DKIM Verification",group:"Authentication",state:"fail",score:10,result:"The message has no valid cryptographic DKIM signature.",recommendation:"Do not rely on the visible From address."},
  {name:"DMARC Alignment",group:"Authentication",state:"fail",score:15,result:"The visible sender does not align with authenticated mail domains.",recommendation:"Quarantine until the sender is independently verified."},
  {name:"Header Consistency",group:"Header forensics",state:"warn",score:7,result:"Return-Path and Reply-To use unrelated domains.",recommendation:"Review the complete Received chain and envelope sender."},
  {name:"Sender IP Analysis",group:"Network",state:"warn",score:5,result:"A private IP address appears in the external delivery route.",recommendation:"Validate the originating relay with the mail administrator."},
  {name:"Domain Reputation",group:"Identity",state:"fail",score:10,result:"The sender domain is newly observed and has no trusted history.",recommendation:"Block the domain pending threat-intelligence verification."},
  {name:"Domain Similarity",group:"Identity",state:"fail",score:13,result:"microsoft-secure-login.co imitates the Microsoft brand.",recommendation:"Add the lookalike domain to the IOC blocklist."},
  {name:"URL & Redirect Analysis",group:"Content",state:"fail",score:9,result:"The login URL resolves outside official Microsoft domains.",recommendation:"Block the URL and search for related messages."},
  {name:"Social Engineering",group:"Content",state:"fail",score:7,result:"Urgency and account-suspension pressure were detected.",recommendation:"Warn recipients not to interact with the message."},
  {name:"Metadata Consistency",group:"Forensics",state:"pass",score:0,result:"No conflicting document timestamps or author fields detected.",recommendation:"No action required for this check."},
  {name:"Message-ID Analysis",group:"Header forensics",state:"pass",score:0,result:"Message-ID format is syntactically valid.",recommendation:"Retain the identifier for mailbox hunting."},
  {name:"Organisation Impersonation",group:"Identity",state:"fail",score:6,result:"The message claims to be Microsoft but uses an unrelated domain.",recommendation:"Report the impersonation domain to the provider."},
];

const malwareChecks:{name:string;state:CheckState;score:number;result:string}[] = [
  {name:"SHA-256 hash generated",state:"pass",score:0,result:"9b7cf42e…8c16e21a"},
  {name:"Extension verification",state:"fail",score:18,result:"Document-like name disguises a Windows executable."},
  {name:"Magic-byte verification",state:"fail",score:14,result:"MZ / PE executable signature detected."},
  {name:"Entropy analysis",state:"warn",score:9,result:"High entropy suggests packing or encryption."},
  {name:"YARA rule analysis",state:"fail",score:24,result:"3 rules matched: loader, credential theft, persistence."},
  {name:"PE header analysis",state:"fail",score:12,result:"Suspicious process and network imports detected."},
  {name:"String analysis",state:"warn",score:8,result:"PowerShell and encoded-command strings found."},
  {name:"Reputation lookup",state:"fail",score:15,result:"Hash is associated with a known malicious sample."},
];

const nav: {label:Module; icon:typeof Inbox; number:string}[] = [
  {label:"Inbox",icon:Inbox,number:"01"},{label:"Email Analysis",icon:FileSearch,number:"02"},
  {label:"Malware Analyser",icon:Bug,number:"03"},{label:"Risk Assessment",icon:Gauge,number:"04"},
  {label:"Reports",icon:FileCode2,number:"05"},
];

const nazarioBatch = {
  dataset: "Jose Nazario Phishing Corpus",
  analysed: 2274,
  malicious: 1049,
  suspicious: 1006,
  lowRisk: 219,
  parsingErrors: 5,
  detectionCoverage: 90.37,
  processingSuccess: 99.78,
};

function StateIcon({state}:{state:CheckState}) {
  return state === "pass" ? <span className="state-icon pass"><Check/></span> : state === "fail" ? <span className="state-icon fail"><X/></span> : <span className="state-icon warn"><AlertTriangle/></span>;
}

function ScoreRing({score,label}:{score:number;label:string}) {
  const color=score>=80?"#ff5466":score>=40?"#f6b84a":"#36d6a0";
  return <div className="score-unit"><div className="score-ring" style={{background:`conic-gradient(${color} ${score*3.6}deg,rgba(255,255,255,.07) 0)`}}><div><strong>{score}</strong><span>/100</span></div></div><p>{label}</p></div>;
}

export default function Home(){
  const [active,setActive]=useState<Module>("Inbox");
  const [mailItems,setMailItems]=useState<MailItem[]>(demoMails);
  const [selected,setSelected]=useState<MailItem>(demoMails[0]);
  const [analysisStep,setAnalysisStep]=useState(12);
  const [malwareStep,setMalwareStep]=useState(8);
  const [menuOpen,setMenuOpen]=useState(false);
  const [query,setQuery]=useState("");
  const [connection,setConnection]=useState<ConnectionState>("idle");
  const [connectionMessage,setConnectionMessage]=useState("Start the local Gmail connector, then connect here.");
  const [analysisChecks,setAnalysisChecks]=useState<AnalysisCheck[]>(demoChecks);
  const [scanState,setScanState]=useState<ScanState>("idle");
  const [scanMessage,setScanMessage]=useState("Ready to analyse the selected message.");
  const filtered=useMemo(()=>mailItems.filter(m=>`${m.sender} ${m.email} ${m.subject}`.toLowerCase().includes(query.toLowerCase())),[mailItems,query]);

  const connectGmail=async()=>{
    setConnection("connecting");
    setConnectionMessage("Contacting the Gmail connector on this computer…");
    try{
      const response=await fetch(GMAIL_CONNECTOR_URL,{cache:"no-store"});
      if(!response.ok)throw new Error(`Connector returned ${response.status}`);
      const data=await response.json() as {connected:boolean;emails:GmailMessage[]};
      const liveMails=(data.emails||[]).map((message)=>{
        const addressMatch=message.from.match(/<([^>]+)>/);
        const address=(addressMatch?.[1]||message.from).replaceAll('"',"").trim();
        const name=(addressMatch?message.from.slice(0,message.from.indexOf("<")):address.split("@")[0]).replaceAll('"',"").trim()||"Unknown sender";
        const initials=name.split(/\s+/).slice(0,2).map(part=>part[0]?.toUpperCase()).join("")||"?";
        const parsedDate=new Date(message.date);
        const time=Number.isNaN(parsedDate.getTime())?message.date:parsedDate.toLocaleString([], {month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"});
        const scanned=message.scan?.status==="complete";
        return {id:`GM-${message.id.slice(-6).toUpperCase()}`,gmailId:message.id,sender:name,email:address,subject:message.subject||"(No subject)",preview:message.snippet||"No message preview available.",time,score:message.scan?.score??0,risk:message.scan?.severity??"safe" as MailRisk,unread:message.labels?.includes("UNREAD"),initials,source:"gmail" as const,scanned,scannedAt:message.scan?.scanned_at};
      });
      if(!liveMails.length)throw new Error("No inbox messages were returned");
      setMailItems(liveMails);
      setSelected(liveMails[0]);
      setAnalysisChecks([]);setScanState("idle");setScanMessage("Ready to analyse the selected message.");
      setConnection("connected");
      setConnectionMessage(`${liveMails.length} live Gmail messages loaded. Refresh to check for new mail.`);
    }catch(error){
      setConnection("error");
      setConnectionMessage("Could not reach the local connector. Keep the API window running and try again.");
      console.error(error);
    }
  };

  const animateChecks=(length:number)=>{
    let step=0;const timer=window.setInterval(()=>{step+=1;setAnalysisStep(step);if(step>=length)window.clearInterval(timer)},240);
  };

  const startEmailAnalysis=async(mail=selected,force=false)=>{
    setSelected(mail);setActive("Email Analysis");setAnalysisStep(0);
    if(mail.source!=="gmail"){
      setAnalysisChecks(demoChecks);setScanState("complete");animateChecks(demoChecks.length);return;
    }
    if(!mail.gmailId){setScanState("error");setScanMessage("The Gmail message ID is missing. Refresh the inbox and try again.");return;}
    setAnalysisChecks([]);setScanState("loading");setScanMessage("Retrieving the original headers and running 12 checks…");
    try{
      const forceQuery=force?"?force=true":"";
      const response=await fetch(`${GMAIL_CONNECTOR_BASE}/api/messages/${encodeURIComponent(mail.gmailId)}/analysis${forceQuery}`,{cache:"no-store"});
      if(!response.ok)throw new Error(`Scanner returned ${response.status}`);
      const result=await response.json() as {score:number;severity:MailRisk;verdict:string;checks:AnalysisCheck[];scanned_at?:string;cached?:boolean;evidence?:{attachments?:{filename:string}[]}};
      const firstAttachment=result.evidence?.attachments?.[0]?.filename;
      const updated={...mail,score:result.score,risk:result.severity,scanned:true,scannedAt:result.scanned_at,attachment:firstAttachment};
      setSelected(updated);
      setMailItems(items=>items.map(item=>item.gmailId===mail.gmailId?updated:item));
      setAnalysisChecks(result.checks);
      setScanState("complete");setScanMessage(`${result.verdict} · ${result.score}/100${result.cached?" · saved result":""}`);
      animateChecks(result.checks.length);
    }catch(error){
      setScanState("error");setScanMessage("The scanner endpoint could not analyse this message. Replace api.py, restart it, and try again.");console.error(error);
    }
  };
  const startMalware=()=>{
    setActive("Malware Analyser");setMalwareStep(0);let step=0;
    const timer=window.setInterval(()=>{step+=1;setMalwareStep(step);if(step>=malwareChecks.length)window.clearInterval(timer)},330);
  };
  const go=(module:Module)=>{setActive(module);setMenuOpen(false)};
  const exportReport=()=>{
    const content=`PHISHGUARD DFIR INCIDENT REPORT\nCase: ${selected.id}\nSeverity: CRITICAL\nComposite risk: 97/100\n\nNAZARIO CORPUS BATCH ANALYSIS\nSuccessfully analysed: ${nazarioBatch.analysed}\nMalicious: ${nazarioBatch.malicious}\nSuspicious: ${nazarioBatch.suspicious}\nLow risk: ${nazarioBatch.lowRisk}\nParsing errors: ${nazarioBatch.parsingErrors}\nDetection coverage: ${nazarioBatch.detectionCoverage}%\n\nNote: The corpus result demonstrates batch detection coverage and pipeline processing, not independent model accuracy.\n\nExecutive Summary\nA credential-phishing email impersonated Microsoft and delivered a disguised Windows executable. Sender authentication failed, the linked domain was a lookalike, and the attachment matched malicious YARA rules.\n\nRecommended Actions\n1. Quarantine the email.\n2. Block sender domain, URL and file hash.\n3. Hunt for matching messages across mailboxes.\n4. Reset credentials and revoke sessions for affected users.\n5. Preserve evidence under case ${selected.id}.`;
    const blob=new Blob([content],{type:"text/plain"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`${selected.id}-incident-report.txt`;a.click();URL.revokeObjectURL(url);
  };

  useEffect(()=>{
    const context=(document as Document&{modelContext?:{registerTool?:(tool:unknown)=>void}}).modelContext;
    context?.registerTool?.({name:"open_security_case",title:"Open security case",description:"Open a PhishGuard demo case by case ID.",inputSchema:{type:"object",properties:{caseId:{type:"string"}},required:["caseId"],additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:true},execute:async(input:{caseId:string})=>{const mail=demoMails.find(m=>m.id===input.caseId)||demoMails[0];startEmailAnalysis(mail);return{caseId:mail.id,status:"analysis_started"}}});
  },[]);

  return <main className="shell">
    <aside className={`sidebar ${menuOpen?"open":""}`}>
      <div className="brand"><span><ShieldAlert/></span><div>PHISH<strong>GUARD</strong><small>DFIR SECURITY OPERATIONS</small></div></div>
      <button className="close-nav" onClick={()=>setMenuOpen(false)} aria-label="Close menu"><X/></button>
      <p className="nav-label">Investigation workflow</p>
      <nav>{nav.map(({label,icon:Icon,number})=><button key={label} className={active===label?"active":""} onClick={()=>go(label)}><span className="nav-number">{number}</span><Icon/><span>{label}</span>{label==="Inbox"&&<em>{mailItems.length}</em>}<ChevronRight className="chevron"/></button>)}</nav>
      <div className="pipeline-card"><div><Activity/><strong>Pipeline status</strong><span className="online-dot"/></div><p>Mail intake and static engines ready</p><div className="mini-status"><span>MAIL</span><i/><span>YARA</span><i/><span>INTEL</span></div></div>
      <div className="analyst"><span>SA</span><div><strong>Security Analyst</strong><small>Protected workspace</small></div><Settings/></div>
    </aside>
    {menuOpen&&<button className="scrim" aria-label="Close navigation" onClick={()=>setMenuOpen(false)}/>} 

    <section className="main">
      <header className="topbar"><div><button className="menu" onClick={()=>setMenuOpen(true)} aria-label="Open menu"><Menu/></button><span>PHISHGUARD /</span><strong>{active.toUpperCase()}</strong></div><div className="top-actions"><span className={`engine-online ${connection}`}><i/> {connection==="connected"?"GMAIL CONNECTED":"SECURITY ENGINES ONLINE"}</span><Dialog><DialogTrigger asChild><Button className="mail-connect"><Mail/> {connection==="connected"?"Live Gmail":"Connect Gmail"}</Button></DialogTrigger><DialogContent className="connect-dialog"><DialogHeader><DialogTitle>Connect your test Gmail inbox</DialogTitle><DialogDescription>PhishGuard reads mail through the OAuth connector running on this computer. Your Gmail password and OAuth files stay on your device.</DialogDescription></DialogHeader><div className={`connector-status ${connection}`}><span>{connection==="connecting"?<RefreshCw className="spin"/>:<Mail/>}</span><div><strong>{connection==="connected"?"Gmail is connected":connection==="error"?"Connection unsuccessful":"Local Gmail connector"}</strong><p>{connectionMessage}</p></div></div><Button className="connector-action" onClick={connectGmail} disabled={connection==="connecting"}>{connection==="connecting"?<><RefreshCw className="spin"/> Connecting…</>:<><RefreshCw/> {connection==="connected"?"Refresh inbox":"Connect Gmail inbox"}</>}</Button><div className="secure-note"><LockKeyhole/><p><strong>Local test pipeline</strong><br/>Keep the Command Prompt running. This connection loads email metadata only; attachment downloading and malware execution remain disabled.</p></div></DialogContent></Dialog></div></header>
      <div className="stage">
        {active==="Inbox"&&<InboxModule query={query} setQuery={setQuery} mails={filtered} selected={selected} onSelect={setSelected} onAnalyse={startEmailAnalysis} connection={connection} onRefresh={connectGmail}/>} 
        {active==="Email Analysis"&&<EmailModule selected={selected} step={analysisStep} checks={analysisChecks} scanState={scanState} scanMessage={scanMessage} onRun={()=>startEmailAnalysis(selected,true)} onMalware={startMalware}/>} 
        {active==="Malware Analyser"&&<MalwareModule selected={selected} step={malwareStep} onRun={startMalware} onRisk={()=>go("Risk Assessment")}/>} 
        {active==="Risk Assessment"&&<RiskModule selected={selected} onReport={()=>go("Reports")}/>} 
        {active==="Reports"&&<ReportsModule selected={selected} onExport={exportReport}/>} 
      </div>
    </section>
    <Dialog><DialogTrigger asChild><Button className="ai-button"><Sparkles/> Ask AI Security Analyst</Button></DialogTrigger><DialogContent className="connect-dialog ai-dialog"><DialogHeader><DialogTitle>AI Security Analyst</DialogTitle><DialogDescription>Evidence-based explanation for case {selected.id}</DialogDescription></DialogHeader><div className="ai-answer"><Bot/><div><strong>Why is this email malicious?</strong><p>The sender failed SPF, DKIM and DMARC checks, uses a Microsoft lookalike domain, applies urgent account-suspension pressure, and delivers a disguised executable. The attachment also matches three malware rules. Together, these signals produce a critical risk score.</p></div></div><div className="ai-chips"><button>What should the SOC do next?</button><button>Explain the YARA matches</button><button>Summarise for management</button></div></DialogContent></Dialog>
  </main>;
}

function PageTitle({eyebrow,title,description,children}:{eyebrow:string;title:string;description:string;children?:React.ReactNode}){return <div className="page-title"><div><span>{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{children}</div>}

function InboxModule({query,setQuery,mails,selected,onSelect,onAnalyse,connection,onRefresh}:{query:string;setQuery:(v:string)=>void;mails:MailItem[];selected:MailItem;onSelect:(m:MailItem)=>void;onAnalyse:(m:MailItem)=>void;connection:ConnectionState;onRefresh:()=>void}){
  const live=connection==="connected";
  return <><PageTitle eyebrow="REAL-TIME MAIL INTAKE" title="Security inbox" description="Review incoming messages and send selected evidence into the PhishGuard analysis pipeline."><div className={`demo-pill ${live?"live":""}`}><span/> {live?`LIVE GMAIL · ${mails.length} MESSAGES`:`DEMO MAILBOX · ${mails.length} MESSAGES`}</div></PageTitle><div className="stats"><div><Inbox/><span>Messages loaded<strong>{mails.length}</strong></span><small>{live?"From connected Gmail":"Controlled test data"}</small></div><div><ShieldAlert/><span>High-risk mail<strong>{live?mails.filter(mail=>mail.scanned&&["critical","high"].includes(mail.risk)).length:"3"}</strong></span><small className="red">{live?"Based on completed scans":"Requires review"}</small></div><div><Clock3/><span>Pending analysis<strong>{live?mails.filter(mail=>!mail.scanned).length:"2"}</strong></span><small>{live?"Only unscanned messages":"Queue under 1 min"}</small></div><div><ShieldCheck/><span>Low-risk scans<strong>{live?mails.filter(mail=>mail.scanned&&mail.risk==="safe").length:"19"}</strong></span><small className="green">{live?"Saved scan history":"No threats found"}</small></div></div><section className="inbox-layout"><div className="mail-list"><div className="mail-tools"><div><Search/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search sender, subject or address"/></div><Button variant="ghost" size="icon" onClick={onRefresh} aria-label="Refresh Gmail inbox"><RefreshCw/></Button></div><div className="mail-rows">{mails.map(mail=><button key={mail.id} className={`${selected.id===mail.id?"selected":""} ${mail.unread?"unread":""}`} onClick={()=>onSelect(mail)}><i className={`risk-dot ${mail.scanned===false?"pending":mail.risk}`}/><span className="avatar">{mail.initials}</span><div><strong>{mail.sender}</strong><small>{mail.subject}</small><p>{mail.preview}</p></div><aside><time>{mail.time}</time>{mail.attachment&&<Badge>📎 {mail.attachment.split(".").at(-1)}</Badge>}<em className={mail.scanned===false?"pending":mail.risk}>{mail.scanned===false?"PENDING":mail.score}</em></aside></button>)}</div></div><div className="mail-preview"><div className="preview-head"><span className="case">CASE {selected.id}</span><Badge className={`risk-badge ${selected.scanned===false?"pending":selected.risk}`}>{selected.scanned===false?"NOT SCANNED":`${selected.score} RISK`}</Badge></div><h2>{selected.subject}</h2><div className="sender-card"><span>{selected.initials}</span><div><strong>{selected.sender}</strong><small>{selected.email}</small></div></div><p className="message-preview">{selected.preview} External links and attachments are disabled in this preview.</p>{selected.attachment&&<div className="attachment"><FileCode2/><div><strong>{selected.attachment}</strong><small>Attachment identified · Not downloaded</small></div><LockKeyhole/></div>}<div className="preview-warning"><TriangleAlert/><p><strong>{selected.scanned?"First-stage scan complete":selected.source==="gmail"?"Ready for live analysis":"Pre-scan warning"}</strong>{selected.scanned?`Saved result: ${selected.score}/100. Open it below or use Run again from the analysis page.`:selected.source==="gmail"?"PhishGuard will retrieve the original headers and message content through your local read-only connector.":"Sender reputation and domain similarity signals require a full analysis."}</p></div><Button className="primary-action" onClick={()=>onAnalyse(selected)}><Play/> {selected.scanned?"View saved analysis":"Analyse this email"}</Button></div></section></>;
}

function EmailModule({selected,step,checks,scanState,scanMessage,onRun,onMalware}:{selected:MailItem;step:number;checks:AnalysisCheck[];scanState:ScanState;scanMessage:string;onRun:()=>void;onMalware:()=>void}){
  if(selected.source==="gmail"&&(scanState==="loading"||scanState==="error")){
    return <><PageTitle eyebrow={`CASE ${selected.id} · MODULE 02`} title="Email forensic analysis" description="The local scanner retrieves the original message and returns an explainable, evidence-based result."/><section className={`scan-bridge ${scanState}`}><span>{scanState==="loading"?<RefreshCw className="spin"/>:<XCircle/>}</span><div><small>{scanState==="loading"?"LIVE ANALYSIS RUNNING":"SCANNER CONNECTION ERROR"}</small><h2>{scanState==="loading"?"Checking the selected Gmail message":"Analysis could not start"}</h2><p>{scanMessage}</p>{scanState==="error"&&<Button onClick={onRun}><RefreshCw/> Try again</Button>}</div></section></>;
  }
  const complete=Math.min(step,checks.length);const risk=checks.slice(0,complete).reduce((a,c)=>a+c.score,0);
  return <><PageTitle eyebrow={`CASE ${selected.id} · MODULE 02`} title="Email forensic analysis" description="Twelve explainable security checks validate the sender, route, content and organisation identity."><div className="title-actions"><Button variant="outline" onClick={onRun}><RefreshCw/> Run again</Button>{selected.attachment&&<Button onClick={onMalware}><Bug/> Analyse attachment</Button>}</div></PageTitle><section className="analysis-summary"><div className="message-ident"><span>{selected.initials}</span><div><small>{selected.source==="gmail"?"LIVE GMAIL MESSAGE":"SELECTED MESSAGE"}</small><strong>{selected.subject}</strong><p>{selected.email}</p></div></div><div className="progress-block"><div><span>ANALYSIS PROGRESS</span><strong>{complete}/{checks.length} checks</strong></div><Progress value={checks.length?complete/checks.length*100:0}/></div><ScoreRing score={Math.min(risk,100)} label="Email risk"/></section>{selected.source==="gmail"&&scanState==="complete"&&<div className="live-analysis-note"><ShieldCheck/><p><strong>Live first-stage result:</strong> {scanMessage}. This score is based on message headers, content patterns, links and attachment names. Reputation services and malware detonation are not included yet.</p></div>}<section className="checklist"><div className="section-head"><div><Fingerprint/><strong>Email security checklist</strong></div><span><i className="legend pass"/> Pass <i className="legend warn"/> Suspicious <i className="legend fail"/> Fail</span></div>{checks.map((check,index)=><article key={check.name} className={index>=step?"pending":""}>{index<step?<StateIcon state={check.state}/>:<span className="state-icon pending-icon">{index===step?<RefreshCw className="spin"/>:<Circle/>}</span>}<div className="check-copy"><span>{check.group}</span><strong>{check.name}</strong>{index<step&&<><p>{check.result}</p><small>Recommendation: {check.recommendation}</small></>}</div>{index<step&&<div className={`risk-points ${check.state}`}>{check.score?`+${check.score}`:"0"}<span>RISK</span></div>}</article>)}</section></>;
}

function MalwareModule({selected,step,onRun,onRisk}:{selected:MailItem;step:number;onRun:()=>void;onRisk:()=>void}){
  const complete=Math.min(step,malwareChecks.length);const risk=Math.min(96,malwareChecks.slice(0,complete).reduce((a,c)=>a+c.score,0));
  return <><PageTitle eyebrow={`CASE ${selected.id} · MODULE 03`} title="Malware analyser" description="The attachment is copied into an isolated workflow for static inspection and approved sandbox analysis."><div className="sandbox-status"><span/><div><small>ISOLATION</small><strong>Sandbox boundary active</strong></div></div></PageTitle><section className="sandbox-map"><div className="sample-card"><FileCode2/><div><small>ISOLATED SAMPLE</small><strong>{selected.attachment||"No attachment selected"}</strong><p>428 KB · SHA-256: 9b7cf42e…8c16e21a</p></div></div><ChevronRight/><div className="sandbox-box"><LockKeyhole/><div><small>DETONATION CHAMBER</small><strong>Restricted VM · No host access</strong><p>Network: controlled · Snapshot: clean</p></div><Badge>DEMO</Badge></div><ChevronRight/><ScoreRing score={risk} label="Threat score"/></section><div className="sandbox-caution"><ServerCog/><p><strong>Hackathon-safe implementation:</strong> the interface demonstrates the isolated workflow. Actual detonation requires a separately deployed Cuckoo/CAPE sandbox. This website never executes the attachment on your device.</p></div><section className="malware-grid"><div className="malware-checks"><div className="section-head"><div><Bug/><strong>Attachment safety checks</strong></div><Button size="sm" variant="outline" onClick={onRun}><Play/> Start isolated analysis</Button></div>{malwareChecks.map((check,index)=><article key={check.name} className={index>=step?"pending":""}>{index<step?<StateIcon state={check.state}/>:<span className="state-icon pending-icon">{index===step?<RefreshCw className="spin"/>:<Circle/>}</span>}<div><strong>{check.name}</strong>{index<step&&<p>{check.result}</p>}</div>{index<step&&check.score>0&&<span className="mal-score">+{check.score}</span>}</article>)}</div><aside className="malware-profile"><span>MALWARE PROFILE</span><h3>Credential-stealing loader</h3><Badge className="critical-tag">CRITICAL</Badge><dl><div><dt>Classification</dt><dd>Trojan / Loader</dd></div><div><dt>File type</dt><dd>Windows PE32</dd></div><div><dt>YARA matches</dt><dd>3 malicious rules</dd></div><div><dt>Reputation</dt><dd>Known malicious</dd></div><div><dt>MITRE ATT&CK</dt><dd>T1204.002</dd></div></dl><Button onClick={onRisk}>Open risk correlation <ChevronRight/></Button></aside></section></>;
}

function RiskModule({selected,onReport}:{selected:MailItem;onReport:()=>void}){
  return <><PageTitle eyebrow={`CASE ${selected.id} · MODULE 04`} title="Unified risk assessment" description="Email, attachment and threat-intelligence evidence are correlated into one defensible decision."/><section className="risk-hero"><div className="equation"><ScoreRing score={94} label="Email risk"/><span>+</span><ScoreRing score={96} label="Malware threat"/><span>+</span><ScoreRing score={88} label="Threat intelligence"/><ChevronRight/><div className="composite"><small>COMPOSITE RISK</small><strong>97</strong><span>/100 · CRITICAL</span></div></div><div className="correlation"><Sparkles/><div><span>AI-ASSISTED CORRELATION</span><h3>Confirmed phishing delivery with a malicious executable</h3><p>The attachment materially increases the overall severity. The message impersonates Microsoft, fails sender authentication, links to a lookalike login domain, and carries a disguised PE executable that matches multiple malware rules.</p></div></div></section><section className="risk-columns"><div><div className="section-head"><div><Network/><strong>Primary risk drivers</strong></div></div>{[["Sender authentication failure",37],["Lookalike domain and URL",22],["Malicious attachment",31],["Social-engineering pressure",7]].map(([label,value])=><div className="driver" key={String(label)}><span>{label}</span><div><i style={{width:`${Number(value)*2.35}%`}}/></div><strong>+{value}</strong></div>)}</div><div className="decision"><span>OVERALL VERDICT</span><h2><ShieldAlert/> MALICIOUS</h2><p>Immediate containment and organisation-wide hunting are recommended.</p><Button onClick={onReport}>Generate incident report <ChevronRight/></Button></div></section></>;
}

function ReportsModule({selected,onExport}:{selected:MailItem;onExport:()=>void}){
  const flagged=nazarioBatch.malicious+nazarioBatch.suspicious;
  return <><PageTitle eyebrow={`CASE ${selected.id} · MODULE 05`} title="Security reports" description="Case-level evidence and corpus-scale detection results for SOC review, management reporting and audit records."><Button onClick={onExport}><Download/> Export report</Button></PageTitle><section className="batch-report"><header><div className="batch-mark"><FileSearch/></div><div><span>OFFLINE CORPUS ANALYSIS</span><h2>{nazarioBatch.dataset}</h2><p>Raw MIME email processing · complete batch snapshot</p></div><Badge className="batch-tag">BATCH EVIDENCE</Badge></header><div className="batch-metrics"><article><span>EMAILS ANALYSED</span><strong>{nazarioBatch.analysed.toLocaleString()}</strong><small>{nazarioBatch.processingSuccess}% processing success</small></article><article className="malicious"><span>MALICIOUS</span><strong>{nazarioBatch.malicious.toLocaleString()}</strong><small>46.13% of analysed mail</small></article><article className="suspicious"><span>SUSPICIOUS</span><strong>{nazarioBatch.suspicious.toLocaleString()}</strong><small>44.24% of analysed mail</small></article><article className="safe"><span>LOW RISK</span><strong>{nazarioBatch.lowRisk.toLocaleString()}</strong><small>9.63% require review</small></article><article className="errors"><span>PARSING ERRORS</span><strong>{nazarioBatch.parsingErrors}</strong><small>0.22% of attempted mail</small></article></div><div className="batch-coverage"><div className="coverage-ring" style={{background:`conic-gradient(#35d7e5 ${nazarioBatch.detectionCoverage*3.6}deg,rgba(255,255,255,.06) 0)`}}><div><strong>{nazarioBatch.detectionCoverage}%</strong><span>DETECTION<br/>COVERAGE</span></div></div><div className="coverage-copy"><span>CORPUS DETECTION RESULT</span><h3>{flagged.toLocaleString()} phishing emails flagged for analyst attention</h3><p>Messages classified as malicious or suspicious are counted as detected. Low-risk results remain visible for false-negative review and rule improvement.</p><div className="coverage-bar"><i style={{width:`${nazarioBatch.detectionCoverage}%`}}/></div><div className="coverage-labels"><span>0%</span><strong>{flagged.toLocaleString()} flagged</strong><span>100%</span></div></div></div><footer><AlertTriangle/><p><strong>Interpretation:</strong> This is corpus detection coverage and pipeline-processing evidence, not independent model accuracy, because Nazario-derived samples were included during model development.</p></footer></section><section className="report"><header><div className="report-mark"><ShieldAlert/></div><div><span>PHISHGUARD DFIR</span><h2>Security Incident Assessment Report</h2><p>Phishing email and malware attachment investigation</p></div><Badge className="critical-tag">CRITICAL</Badge></header><div className="report-meta"><div><span>CASE ID</span><strong>{selected.id}</strong></div><div><span>ASSESSMENT DATE</span><strong>17 September 2026</strong></div><div><span>COMPOSITE RISK</span><strong className="red-text">97 / 100</strong></div><div><span>STATUS</span><strong>Containment required</strong></div></div><section><span className="report-number">01</span><div><h3>Executive summary</h3><p>A credential-phishing email impersonating Microsoft was delivered with a disguised Windows executable. The message failed sender-authentication checks, used a lookalike domain, and applied urgent account-suspension pressure. The attachment matched three malicious detection rules and is assessed as a credential-stealing loader.</p></div></section><section><span className="report-number">02</span><div><h3>Key findings</h3><Table><TableHeader><TableRow><TableHead>Finding</TableHead><TableHead>Evidence</TableHead><TableHead>Severity</TableHead></TableRow></TableHeader><TableBody><TableRow><TableCell>Sender spoofing</TableCell><TableCell>SPF, DKIM and DMARC failed</TableCell><TableCell><Badge className="critical-tag">Critical</Badge></TableCell></TableRow><TableRow><TableCell>Domain impersonation</TableCell><TableCell>microsoft-secure-login.co</TableCell><TableCell><Badge className="high-tag">High</Badge></TableCell></TableRow><TableRow><TableCell>Malicious attachment</TableCell><TableCell>PE executable, 3 YARA matches</TableCell><TableCell><Badge className="critical-tag">Critical</Badge></TableCell></TableRow></TableBody></Table></div></section><section><span className="report-number">03</span><div><h3>Indicators of compromise</h3><div className="ioc-grid"><div><span>DOMAIN</span><code>microsoft-secure-login.co</code></div><div><span>URL</span><code>hxxps://microsoft-security-check[.]co/login</code></div><div><span>FILE</span><code>{selected.attachment}</code></div><div><span>SHA-256</span><code>9b7cf42e…8c16e21a</code></div></div></div></section><section><span className="report-number">04</span><div><h3>Recommended protective measures</h3><ol><li><strong>Immediate containment:</strong> Quarantine the email and block the sender, reply-to domain, URL and file hash.</li><li><strong>Organisation-wide hunting:</strong> Search all mailboxes and endpoint telemetry for the same indicators.</li><li><strong>Identity protection:</strong> Reset credentials, revoke sessions and review MFA events for users who interacted.</li><li><strong>Endpoint response:</strong> Isolate affected devices and preserve volatile and disk evidence.</li><li><strong>Preventive control:</strong> Strengthen DMARC enforcement, attachment controls and phishing-awareness simulations.</li></ol></div></section><footer><Fingerprint/> Evidence preserved under case {selected.id} · Chain-of-custody timestamps retained</footer></section></>;
}
