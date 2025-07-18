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
                      <span className="text-green-300">Mission:</span> Securing the digital world, one vulnerability at
                      a time
                    </p>
                    <p>
                      <span className="text-green-300">Specialization:</span> Web Application Security, Network
                      Penetration Testing, Malware Analysis
                    </p>
                    <p>
                      <span className="text-green-300">Philosophy:</span> "The best defense is understanding the
                      offense"
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
                        Active bug bounty hunter with multiple CVEs discovered. Specialized in finding and responsibly
                        disclosing security vulnerabilities in web applications and network infrastructure.
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
                        Experienced in conducting comprehensive security assessments, from reconnaissance to
                        post-exploitation. Proficient with industry-standard tools and methodologies.
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
                        Creator of custom security tools and automation scripts. Passionate about developing solutions
                        that make security testing more efficient and effective.
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
                        Volunteer mentor for aspiring cybersecurity professionals. Conduct workshops on ethical hacking,
                        secure coding practices, and career guidance. Active in local cybersecurity meetups and
                        conferences.
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
                        Active contributor to open source security projects and tools. Maintain security-focused
                        repositories, review code for vulnerabilities, and contribute to community-driven security
                        initiatives.
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
                        Volunteer educator promoting cybersecurity awareness in schools and community organizations.
                        Develop educational content on digital privacy, safe browsing, and social engineering
                        prevention.
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
                        Organized and facilitated Capture The Flag competitions for local universities and hacker
                        communities. Created challenging scenarios and provided mentorship to participants learning
                        ethical hacking.
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

                    </div>
                    <div className="bg-black/30 border border-green-400/30 rounded p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <Award className="w-5 h-5 text-green-300 flex-shrink-0" />
                          <h3 className="font-semibold text-green-300">CyberWise WiseCamp</h3>
                        </div>
                      </div>
                      <p className="text-sm text-green-400/70 mt-1">
                        Industry-standard certification covering core cybersecurity skills including network security,
                        compliance, operational security, threats and vulnerabilities, and cryptography.
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
                        Hands-on penetration testing certification requiring practical exploitation of vulnerable
                        machines. Demonstrates advanced skills in enumeration, exploitation, and privilege escalation.
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
                        Advanced certification focusing on security architecture, engineering, and management. Currently
                        preparing for examination with expected completion in Q2 2024.
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
                        Advanced certification focusing on security architecture, engineering, and management. Currently
                        preparing for examination with expected completion in Q2 2024.
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
                        Advanced certification focusing on security architecture, engineering, and management. Currently
                        preparing for examination with expected completion in Q2 2024.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h2 className="text-xl font-semibold text-green-300">$ ls -la skills/</h2>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {[
                      "Python",
                      "Bash/Shell",
                      "JavaScript",
                      "Go",
                      "C/C++",
                      "Burp Suite",
                      "Metasploit",
                      "Nmap",
                      "Wireshark",
                      "OWASP ZAP",
                      "Linux",
                      "Windows",
                      "Docker",
                      "AWS",
                      "GCP",
                      "OSINT",
                      "Social Engineering",
                      "Cryptography",
                      "Forensics",
                      "Reverse Engineering",
                    ].map((skill, index) => (
                      <div key={index} className="skill-tag">
                        {skill}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-8 text-center">
                  <p className="text-green-400/70">
                    root@wepliep:~/about$ echo "Always learning, always hacking ethically"
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
