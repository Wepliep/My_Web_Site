"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { Terminal, ArrowLeft, Shield, Code, Zap, Calendar, Award } from "lucide-react"

export default function AboutPage() {
  const [showContent, setShowContent] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setShowContent(true), 500)
    return () => clearTimeout(timer)
  }, [])

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none">
        <div className="scanlines"></div>
      </div>
      <div className="matrix-bg"></div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <header className="border-b border-green-400/30 pb-4 mb-8">
          <div className="flex items-center justify-between">
            <Link href="/" className="flex items-center space-x-2 hover:text-green-300 transition-colors">
              <Terminal className="w-6 h-6" />
              <span className="text-xl font-bold">Wepliep</span>
            </Link>
            <Link href="/" className="flex items-center space-x-2 hover:text-green-300 transition-colors">
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Terminal</span>
            </Link>
          </div>
        </header>

        <main className="max-w-6xl mx-auto">
          <div className="terminal-window bg-black/50 border border-green-400/50 rounded-lg p-8 backdrop-blur-sm">
            <div className="flex items-center space-x-2 mb-6 text-sm">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="ml-4 text-green-400/70">about.txt</span>
            </div>

            {showContent && (
              <div className="space-y-6 animate-fade-in">
                <div>
                  <h1 className="text-3xl font-bold mb-4 text-green-300">root@wepliep:~/about$ cat profile.txt</h1>
                  <div className="typing-text">
                    <p className="text-lg mb-4">{">"} Initializing user profile...</p>
                  </div>
                  <div className="mb-8">
                    <pre className="text-green-300 text-center font-mono text-sm leading-tight">
                      {`
██╗    ██╗███████╗██████╗ ██╗     ██╗███████╗██████╗ 
██║    ██║██╔════╝██╔══██╗██║     ██║██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝██║     ██║█████╗  ██████╔╝
██║███╗██║██╔══╝  ██╔═══╝ ██║     ██║██╔══╝  ██╔═══╝ 
╚███╔███╔╝███████╗██║     ███████╗██║███████╗██║     
 ╚══╝╚══╝ ╚══════╝╚═╝     ╚══════╝╚═╝╚══════╝╚═╝     
`}
                    </pre>
                    <div className="text-center mt-4">
                      <div className="inline-block border border-green-400/30 rounded px-4 py-2 bg-black/30">
                        <span className="text-green-300 text-sm">[ IDENTITY CONFIRMED ]</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                  <div className="stat-card">
                    <Shield className="w-8 h-8 mb-2 text-green-300" />
                    <h3 className="text-lg font-semibold">Security Focus</h3>
                    <p className="text-sm text-green-400/70">Penetration Testing & Vulnerability Research</p>
                  </div>
                  <div className="stat-card">
                    <Code className="w-8 h-8 mb-2 text-green-300" />
                    <h3 className="text-lg font-semibold">Development</h3>
                    <p className="text-sm text-green-400/70">Security Tools & Automation Scripts</p>
                  </div>
                  <div className="stat-card">
                    <Zap className="w-8 h-8 mb-2 text-green-300" />
                    <h3 className="text-lg font-semibold">CTF Player</h3>
                    <p className="text-sm text-green-400/70">Competitive Hacking & Problem Solving</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <h2 className="text-xl font-semibold text-green-300">$ whoami</h2>
                  <div className="bg-black/30 border border-green-400/30 rounded p-4 space-y-3">
                    <p>
                      <span className="text-green-300">Name:</span> Erkan ÇEKİÇ
                    </p>
                    <p>
                      <span className="text-green-300">Education:</span> Firat Üniversity, Digital Forensic Engineering (2021 - 2025)
                    </p>
                    <p>
                      <span className="text-green-300">Specialization:</span> Web Application Security, Bug Haunter
                    </p>
                    <p className="flex items-center space-x-2">
                      <span className="text-green-300">E-Mail:</span>
                      <span>{'erkan[dot]cekc' + '[at]' + 'gmail[dot]com'}</span>
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        className="h-4 w-4 text-green-400"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M16 12l-4 4-4-4m0-8l4 4 4-4"
                        />
                      </svg>
                    </p>
                    <p>
                      <span className="text-green-300">LinkedIn:</span> 
                      <a href="https://www.linkedin.com/in/erkanckc0x0001/" target="_blank" rel="noopener noreferrer" className="underline hover:text-green-300">
                          erkanckc0x0001
                      </a>
                    </p>
                  </div>
                </div>

                <div className="space-y-4">
                  <h2 className="text-xl font-semibold text-green-300">$ cat experience.log</h2>
                  <div className="space-y-3">
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-green-300">Penetration Tester Intern --- EMA Security LTD </h3>
                        <div className="flex items-center space-x-1 text-xs text-green-400/70">
                          <Calendar className="w-3 h-3" />
                          <span>Jan 25 - May 25</span>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I worked on vulnerable machine solutions focused on web and system security, documenting 
                        each finding in the form of a pentest report. Throughout my internship, I analyzed and reported 
                        various machines and different types of vulnerabilities.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-green-300">CTI Intern --- Brandefense</h3>
                        <div className="flex items-center space-x-1 text-xs text-green-400/70">
                          <Calendar className="w-3 h-3" />
                          <span>Jul 24 - Oct 24</span>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I have received training and conducted studies on threat analysis, threat intelligence 
                        research, anonymous networks, the importance of OPSEC, CTI report generation techniques, 
                        ransomware groups, deep web investigations, as well as news and target monitoring.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-green-300">Cyber Assurance Security Support Assistant --- GarantiBBVA Technology</h3>
                        <div className="flex items-center space-x-1 text-xs text-green-400/70">
                          <Calendar className="w-3 h-3" />
                          <span>Jun 23 - Dec 23</span>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I have worked on web automatic and manual web vulnerabilities. I have worked on pentest report 
                        generation techniques, vulnerable machine solutions, vulnerability reporting, vulnerability 
                        research, testing processes. I have done research on DAST and SAST processes.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h2 className="text-xl font-semibold text-green-300">$ cat volunteer.log</h2>
                  <div className="space-y-3">
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-green-300">Siber Gölge Podcast --- Publisher</h3>
                        <div className="flex items-center space-x-1 text-xs text-green-400/70">
                          <Calendar className="w-3 h-3" />
                          <span>Present</span>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        In each episode of{" "}
                        <a href="https://open.spotify.com/show/0wJjOblI99y1vP1DAW27Dk" target="_blank" rel="noopener noreferrer" className="underline hover:text-green-300">
                          Siber Gölge
                        </a>
                        , we discuss how cyber threats emerge, how to deal with them, and how to ensure 
                        security in today's digital world. With interviews with expert guests and practical tips, 
                        listeners gain awareness in the field of cyber security and learn how to protect their 
                        digital assets.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-green-300">HacktorX Cyber Security Portal --- Site Admin & Developer</h3>
                        <div className="flex items-center space-x-1 text-xs text-green-400/70">
                          <Calendar className="w-3 h-3" />
                          <span>Present</span>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        <a href="https://hacktorx.com" target="_blank" rel="noopener noreferrer" className="underline hover:text-green-300">
                          HacktorX
                        </a>{" "}
                        is a platform where we produce content and events such as cyber security competitions
                        blogs, articles, cyber security trainings, cyber security chats.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-green-300">Owasp Firat University Student Chapter --- Chapter Lead</h3>
                        <div className="flex items-center space-x-1 text-xs text-green-400/70">
                          <Calendar className="w-3 h-3" />
                          <span>Present</span>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I started this volunteer work to raise awareness about cybersecurity and contribute to the 
                        cybersecurity ecosystem. I organized many cybersecurity events and brought cybersecurity 
                        enthusiasts together.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-green-300">HackTheBox Firat University --- University Representative</h3>
                        <div className="flex items-center space-x-1 text-xs text-green-400/70">
                          <Calendar className="w-3 h-3" />
                          <span>Present</span>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        In this task, I assumed the administration of Fırat University; In 2024, we increased 
                        Fırat University to 1st place in the HackTheBox National ranking and 59th place in the 
                        Global ranking.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h2 className="text-xl font-semibold text-green-300">$ cat certifications.log</h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Award className="w-5 h-5 text-green-300 flex-shrink-0" />
                          <h3 className="font-semibold text-green-300">TurkTelekom Cyber Security Camp 2024</h3>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I had the opportunity to attend the cyber security camp organized by TürkTelekom in 2024. 
                        In this process, I received trainings specific to many sub-disciplines of cyber security.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Award className="w-5 h-5 text-green-300 flex-shrink-0" />
                          <h3 className="font-semibold text-green-300">CyberWise WiseCamp</h3>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I had the opportunity to participate in the WiseCamp training prepared by CyberWise Company 
                        and received trainings in many areas and established new connections.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Award className="w-5 h-5 text-green-300 flex-shrink-0" />
                          <h3 className="font-semibold text-green-300">
                            CISCO CyberOps Associate
                          </h3>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I successfully completed the Cyber Security Analyst Program organized by Akbank through 
                        CISCO and was entitled to receive this certificate in 2021.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Award className="w-5 h-5 text-green-300 flex-shrink-0" />
                          <h3 className="font-semibold text-green-300">
                            CCNA v7: Introduction to Networks
                          </h3>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I successfully completed the Cyber Security Analyst Program organized by Akbank through 
                        CISCO and was entitled to receive this certificate in 2021.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Award className="w-5 h-5 text-green-300 flex-shrink-0" />
                          <h3 className="font-semibold text-green-300">
                            CISCO Introduction to Cybersecurity
                          </h3>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I successfully completed the Cyber Security Analyst Program organized by Akbank through 
                        CISCO and was entitled to receive this certificate in 2021.
                      </p>
                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Award className="w-5 h-5 text-green-300 flex-shrink-0" />
                          <h3 className="font-semibold text-green-300">
                            NDG: Linux Unhatched
                          </h3>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        I successfully completed the Cyber Security Analyst Program organized by Akbank through 
                        CISCO and was entitled to receive this certificate in 2021.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h2 className="text-xl font-semibold text-green-300">$ ls -la skills/</h2>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {[
                      "Node.js",
                      "JavaScript",
                      "Python",
                      "OWASP Top 10",
                      "Postman",
                      "Burp Suite",
                      "Metasploit",
                      "Nmap",
                      "Wireshark",
                      "OWASP ZAP",
                      "Fedora Linux",
                      "Parrot Security OS",
                      "Docker",
                      "Server Administration",
                      "MongoDB",
                      "MySQL",
                      "Cryptography",
                      "Forensics",
                    ].map((skill, index) => (
                      <div key={index} className="skill-tag">
                        {skill}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-8 text-center">
                  <p className="text-green-400/70">
                    root@wepliep:~/about$ echo "Being the best belongs to those who choose to outdo themselves every day."
                  </p>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}
