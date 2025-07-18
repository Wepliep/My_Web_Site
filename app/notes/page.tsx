"use client"

import { useState } from "react"
import Link from "next/link"
import {
  Terminal,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  FileText,
  Shield,
  Code,
  Search,
  Lock,
  Bug,
  Zap,
} from "lucide-react"

const generateSlug = (title: string) => {
  return title
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
}

const notesData = [
  {
    category: "Web Application Security",
    icon: <Shield className="w-5 h-5" />,
    notes: [
      { title: "SQL Injection Cheat Sheet", date: "2024-01-15", tags: ["SQLi", "Database", "OWASP"] },
      { title: "XSS Payload Collection", date: "2024-01-12", tags: ["XSS", "JavaScript", "Payloads"] },
      { title: "CSRF Protection Bypass Techniques", date: "2024-01-10", tags: ["CSRF", "Tokens", "Bypass"] },
      { title: "JWT Security Best Practices", date: "2024-01-08", tags: ["JWT", "Authentication", "Security"] },
    ],
  },
  {
    category: "Network Security",
    icon: <Search className="w-5 h-5" />,
    notes: [
      { title: "Nmap Scanning Techniques", date: "2024-01-14", tags: ["Nmap", "Reconnaissance", "Scanning"] },
      { title: "Wireshark Analysis Tips", date: "2024-01-11", tags: ["Wireshark", "Traffic Analysis", "Forensics"] },
      { title: "VPN Tunneling Protocols", date: "2024-01-09", tags: ["VPN", "Tunneling", "Protocols"] },
      { title: "Firewall Evasion Methods", date: "2024-01-07", tags: ["Firewall", "Evasion", "Bypass"] },
    ],
  },
  {
    category: "Cryptography",
    icon: <Lock className="w-5 h-5" />,
    notes: [
      { title: "RSA Implementation Flaws", date: "2024-01-13", tags: ["RSA", "Cryptography", "Vulnerabilities"] },
      { title: "Hash Collision Attacks", date: "2024-01-06", tags: ["Hashing", "Collisions", "Attacks"] },
      { title: "AES Side-Channel Analysis", date: "2024-01-05", tags: ["AES", "Side-Channel", "Analysis"] },
    ],
  },
  {
    category: "Malware Analysis",
    icon: <Bug className="w-5 h-5" />,
    notes: [
      { title: "Static Analysis with YARA", date: "2024-01-04", tags: ["YARA", "Static Analysis", "Malware"] },
      { title: "Dynamic Analysis Sandbox Setup", date: "2024-01-03", tags: ["Sandbox", "Dynamic Analysis", "VM"] },
      { title: "Reverse Engineering Tools", date: "2024-01-02", tags: ["Reverse Engineering", "Tools", "IDA"] },
    ],
  },
  {
    category: "CTF Writeups",
    icon: <Zap className="w-5 h-5" />,
    notes: [
      { title: "PicoCTF 2024 - Web Challenges", date: "2024-01-01", tags: ["PicoCTF", "Web", "Writeup"] },
      { title: "HackTheBox - Crypto Challenges", date: "2023-12-30", tags: ["HTB", "Crypto", "Writeup"] },
      { title: "OverTheWire Bandit Solutions", date: "2023-12-28", tags: ["OverTheWire", "Linux", "Writeup"] },
    ],
  },
  {
    category: "Tool Development",
    icon: <Code className="w-5 h-5" />,
    notes: [
      { title: "Python Exploit Development", date: "2023-12-27", tags: ["Python", "Exploits", "Development"] },
      { title: "Bash Automation Scripts", date: "2023-12-25", tags: ["Bash", "Automation", "Scripts"] },
      { title: "Go Security Tools", date: "2023-12-23", tags: ["Go", "Security", "Tools"] },
    ],
  },
]

// Update note slugs
notesData[0].notes[0].title = "SQL Injection Cheat Sheet"
notesData[0].notes[1].title = "XSS Payload Collection"
notesData[0].notes[2].title = "CSRF Protection Bypass Techniques"

export default function NotesPage() {
  const [expandedCategories, setExpandedCategories] = useState<string[]>([])
  const [searchTerm, setSearchTerm] = useState("")

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) =>
      prev.includes(category) ? prev.filter((c) => c !== category) : [...prev, category],
    )
  }

  const filteredNotes = notesData
    .map((category) => ({
      ...category,
      notes: category.notes.filter(
        (note) =>
          note.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
          note.tags.some((tag) => tag.toLowerCase().includes(searchTerm.toLowerCase())),
      ),
    }))
    .filter((category) => category.notes.length > 0)

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
              <span className="ml-4 text-green-400/70">knowledge-base.md</span>
            </div>

            <div className="space-y-6">
              <div>
                <h1 className="text-3xl font-bold mb-4 text-green-300">root@wepliep:~/notes$ cat knowledge_base.md</h1>
                <p className="text-green-400/70 mb-6">Cybersecurity notes, writeups, and research findings</p>
              </div>

              {/* Search */}
              <div className="relative mb-6">
                <input
                  type="text"
                  placeholder="Search notes and tags..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-black/30 border border-green-400/30 rounded px-4 py-2 text-green-400 placeholder-green-400/50 focus:border-green-400 focus:outline-none"
                />
                <Search className="absolute right-3 top-2.5 w-4 h-4 text-green-400/50" />
              </div>

              {/* Notes Categories */}
              <div className="space-y-4">
                {filteredNotes.map((category) => (
                  <div key={category.category} className="border border-green-400/30 rounded-lg overflow-hidden">
                    <button
                      onClick={() => toggleCategory(category.category)}
                      className="w-full flex items-center justify-between p-4 bg-black/30 hover:bg-black/50 transition-colors"
                    >
                      <div className="flex items-center space-x-3">
                        <div className="text-green-300">{category.icon}</div>
                        <h2 className="text-lg font-semibold text-green-300">{category.category}</h2>
                        <span className="text-sm text-green-400/50">({category.notes.length})</span>
                      </div>
                      {expandedCategories.includes(category.category) ? (
                        <ChevronDown className="w-5 h-5" />
                      ) : (
                        <ChevronRight className="w-5 h-5" />
                      )}
                    </button>

                    {expandedCategories.includes(category.category) && (
                      <div className="border-t border-green-400/30">
                        {category.notes.map((note, index) => (
                          <Link
                            href={`/notes/${note.title
                              .toLowerCase()
                              .replace(/\s+/g, "-")
                              .replace(/[^a-z0-9-]/g, "")}`}
                            key={index}
                            className="p-4 border-b border-green-400/10 last:border-b-0 hover:bg-black/20 transition-colors cursor-pointer block"
                          >
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center space-x-2 mb-2">
                                  <FileText className="w-4 h-4 text-green-300" />
                                  <h3 className="font-semibold text-green-300">{note.title}</h3>
                                </div>
                                <div className="flex flex-wrap gap-2 mb-2">
                                  {note.tags.map((tag, tagIndex) => (
                                    <span key={tagIndex} className="skill-tag text-xs">
                                      #{tag}
                                    </span>
                                  ))}
                                </div>
                              </div>
                              <span className="text-xs text-green-400/50 ml-4">{note.date}</span>
                            </div>
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {filteredNotes.length === 0 && searchTerm && (
                <div className="text-center py-8">
                  <p className="text-green-400/70">No notes found matching "{searchTerm}"</p>
                </div>
              )}

              <div className="mt-8 text-center">
                <p className="text-green-400/70">
                  root@wepliep:~/notes$ echo "Knowledge is power, share it responsibly"
                </p>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
