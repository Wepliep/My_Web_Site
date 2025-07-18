"use client"

import { useState } from "react"
import Link from "next/link"
import { Terminal, ArrowLeft, Github, ExternalLink, Shield, Code, Zap, Search, Lock, Bug } from "lucide-react"

const projects = [
  {
    id: 1,
    title: "VulnScanner Pro",
    description: "Advanced web application vulnerability scanner with custom payloads and automated reporting.",
    tech: ["Python", "Flask", "SQLite", "BeautifulSoup"],
    category: "Security Tools",
    status: "Active",
    github: "https://github.com/username/vulnscanner",
    demo: null,
    icon: <Shield className="w-6 h-6" />,
  },
  {
    id: 2,
    title: "Payload Generator",
    description: "Dynamic payload generation tool for XSS, SQLi, and command injection testing.",
    tech: ["JavaScript", "Node.js", "Express", "MongoDB"],
    category: "Security Tools",
    status: "Active",
    github: "https://github.com/username/payload-gen",
    demo: "https://payload-gen.demo.com",
    icon: <Code className="w-6 h-6" />,
  },
  {
    id: 3,
    title: "Network Recon Suite",
    description: "Comprehensive network reconnaissance toolkit with stealth scanning capabilities.",
    tech: ["Go", "Cobra CLI", "Nmap", "Masscan"],
    category: "Reconnaissance",
    status: "Beta",
    github: "https://github.com/username/recon-suite",
    demo: null,
    icon: <Search className="w-6 h-6" />,
  },
  {
    id: 4,
    title: "Crypto Challenge Solver",
    description: "Automated cryptographic challenge solver for CTF competitions.",
    tech: ["Python", "PyCrypto", "Sage", "Z3"],
    category: "CTF Tools",
    status: "Active",
    github: "https://github.com/username/crypto-solver",
    demo: null,
    icon: <Lock className="w-6 h-6" />,
  },
  {
    id: 5,
    title: "Bug Bounty Automation",
    description: "Automated reconnaissance and vulnerability discovery pipeline for bug bounty hunting.",
    tech: ["Bash", "Python", "Docker", "Jenkins"],
    category: "Automation",
    status: "Active",
    github: "https://github.com/username/bb-automation",
    demo: null,
    icon: <Bug className="w-6 h-6" />,
  },
  {
    id: 6,
    title: "Malware Analysis Lab",
    description: "Containerized malware analysis environment with automated behavioral analysis.",
    tech: ["Docker", "Python", "YARA", "Volatility"],
    category: "Malware Analysis",
    status: "Development",
    github: "https://github.com/username/malware-lab",
    demo: null,
    icon: <Zap className="w-6 h-6" />,
  },
]

const categories = ["All", "Security Tools", "Reconnaissance", "CTF Tools", "Automation", "Malware Analysis"]

export default function ProjectsPage() {
  const [selectedCategory, setSelectedCategory] = useState("All")

  const filteredProjects =
    selectedCategory === "All" ? projects : projects.filter((project) => project.category === selectedCategory)

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
              <span className="ml-4 text-green-400/70">projects.sh</span>
            </div>

            <div className="space-y-6">
              <div>
                <h1 className="text-3xl font-bold mb-4 text-green-300">root@wepliep:~/projects$ ls -la</h1>
                <p className="text-green-400/70 mb-6">Cybersecurity tools, research projects, and automation scripts</p>
              </div>

              {/* Category Filter */}
              <div className="flex flex-wrap gap-2 mb-8">
                {categories.map((category) => (
                  <button
                    key={category}
                    onClick={() => setSelectedCategory(category)}
                    className={`px-3 py-1 rounded border transition-colors ${
                      selectedCategory === category
                        ? "bg-green-400/20 border-green-400 text-green-300"
                        : "border-green-400/30 hover:border-green-400/50 hover:text-green-300"
                    }`}
                  >
                    {category}
                  </button>
                ))}
              </div>

              {/* Projects Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {filteredProjects.map((project) => (
                  <div key={project.id} className="project-card group">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <div className="text-green-300">{project.icon}</div>
                        <div>
                          <h3 className="text-lg font-semibold text-green-300">{project.title}</h3>
                          <span className="text-xs text-green-400/50">{project.category}</span>
                        </div>
                      </div>
                      <div
                        className={`px-2 py-1 rounded text-xs ${
                          project.status === "Active"
                            ? "bg-green-400/20 text-green-300"
                            : project.status === "Beta"
                              ? "bg-yellow-400/20 text-yellow-300"
                              : "bg-blue-400/20 text-blue-300"
                        }`}
                      >
                        {project.status}
                      </div>
                    </div>

                    <p className="text-green-400/70 mb-4 text-sm leading-relaxed">{project.description}</p>

                    <div className="flex flex-wrap gap-2 mb-4">
                      {project.tech.map((tech, index) => (
                        <span key={index} className="skill-tag text-xs">
                          {tech}
                        </span>
                      ))}
                    </div>

                    <div className="flex items-center space-x-4">
                      {project.github && (
                        <a
                          href={project.github}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center space-x-1 text-sm hover:text-green-300 transition-colors"
                        >
                          <Github className="w-4 h-4" />
                          <span>Code</span>
                        </a>
                      )}
                      {project.demo && (
                        <a
                          href={project.demo}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center space-x-1 text-sm hover:text-green-300 transition-colors"
                        >
                          <ExternalLink className="w-4 h-4" />
                          <span>Demo</span>
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-8 text-center">
                <p className="text-green-400/70">root@wepliep:~/projects$ echo "More projects coming soon..."</p>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
