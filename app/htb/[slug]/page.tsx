"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { Terminal, ArrowLeft, Target, Calendar, Copy, Check, ImageIcon, Flag, List, ChevronRight } from "lucide-react"
import { machineWriteups } from "./machine-writeups"

interface PageProps {
  params: {
    slug: string
  }
}

export default function MachineWriteupPage({ params }: PageProps) {
  const [copied, setCopied] = useState<string | null>(null)
  const [showContent, setShowContent] = useState(false)
  const [activeSection, setActiveSection] = useState<string>("")
  const [scrollY, setScrollY] = useState(0)

  const machine = machineWriteups[params.slug]

  useEffect(() => {
    const timer = setTimeout(() => setShowContent(true), 300)
    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY
      setScrollY(currentScrollY)

      const sections = machine?.sections || []
      const scrollPosition = currentScrollY + 200

      for (let i = sections.length - 1; i >= 0; i--) {
        const element = document.getElementById(sections[i].title.toLowerCase().replace(/\s+/g, "-"))
        if (element && element.offsetTop <= scrollPosition) {
          setActiveSection(sections[i].title)
          break
        }
      }
    }

    window.addEventListener("scroll", handleScroll)
    return () => window.removeEventListener("scroll", handleScroll)
  }, [machine])

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(id)
      setTimeout(() => setCopied(null), 2000)
    } catch (err) {
      console.error("Failed to copy text: ", err)
    }
  }

  const scrollToSection = (sectionTitle: string) => {
    const element = document.getElementById(sectionTitle.toLowerCase().replace(/\s+/g, "-"))
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" })
    }
  }

  // Calculate TOC position based on scroll
  const getTocPosition = () => {
    const baseTop = 132 // Adjusted to align with content card top border
    const scrollOffset = Math.min(scrollY * 0.3, 60) // Move up by 30% of scroll, max 60px
    return Math.max(baseTop - scrollOffset, 20) // Don't go above 20px from top
  }

  if (!machine) {
    return (
      <div className="min-h-screen bg-black text-green-400 font-mono relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="scanlines"></div>
        </div>
        <div className="matrix-bg"></div>
        <div className="relative z-10 container mx-auto px-4 py-8">
          <div className="text-center mt-20">
            <h1 className="text-3xl font-bold text-red-400 mb-4">404 - Machine Not Found</h1>
            <p className="text-green-400/70 mb-8">The requested machine writeup does not exist.</p>
            <Link href="/htb" className="text-green-300 hover:text-green-400 underline">
              Return to HTB Portfolio
            </Link>
          </div>
        </div>
      </div>
    )
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Easy":
        return "text-green-400"
      case "Medium":
        return "text-yellow-400"
      case "Hard":
        return "text-orange-400"
      default:
        return "text-green-400"
    }
  }

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
            <Link href="/htb" className="flex items-center space-x-2 hover:text-green-300 transition-colors">
              <ArrowLeft className="w-4 h-4" />
              <span>Back to HTB</span>
            </Link>
          </div>
        </header>

        <div className="flex gap-8 max-w-7xl mx-auto">
          {/* Table of Contents - Dynamic Positioned Sidebar */}
          <div className="hidden lg:block w-64 flex-shrink-0">
            <div className="fixed w-64 transition-all duration-300 ease-out" style={{ top: `${getTocPosition()}px` }}>
              <div className="bg-black/50 border border-green-400/50 rounded-lg p-4 backdrop-blur-sm max-h-[calc(100vh-8rem)] overflow-y-auto">
                <div className="flex items-center space-x-2 mb-4">
                  <List className="w-4 h-4 text-green-300" />
                  <h3 className="text-sm font-semibold text-green-300">Table of Contents</h3>
                </div>
                <nav className="space-y-2">
                  {machine.sections.map((section, index) => (
                    <button
                      key={index}
                      onClick={() => scrollToSection(section.title)}
                      className={`w-full text-left text-sm py-1 px-2 rounded transition-colors flex items-center space-x-2 ${
                        activeSection === section.title
                          ? "bg-green-400/20 text-green-300"
                          : "text-green-400/70 hover:text-green-300 hover:bg-green-400/10"
                      }`}
                    >
                      <ChevronRight className="w-3 h-3" />
                      <span>{section.title}</span>
                    </button>
                  ))}
                </nav>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <main className="flex-1 min-w-0">
            <div className="terminal-window bg-black/50 border border-green-400/50 rounded-lg p-8 backdrop-blur-sm">
              <div className="flex items-center space-x-2 mb-6 text-sm">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
                <span className="ml-4 text-green-400/70">{machine.name.toLowerCase()}_writeup.md</span>
              </div>

              {showContent && (
                <div className="space-y-6 animate-fade-in">
                  {/* Machine Header */}
                  <div className="border-b border-green-400/30 pb-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <Target className="w-6 h-6 text-green-300" />
                        <h1 className="text-3xl font-bold text-green-300">{machine.name}</h1>
                        <span className="text-lg text-green-400/70">{machine.os}</span>
                        <span className={`text-lg font-semibold ${getDifficultyColor(machine.difficulty)}`}>
                          {machine.difficulty}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-6 text-sm text-green-400/70 mb-4">
                      <div className="flex items-center space-x-2">
                        <Calendar className="w-4 h-4" />
                        <span>Completed: {machine.date}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Flag className="w-4 h-4" />
                        <span>{machine.points} points</span>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2 mb-4">
                      {machine.tags.map((tag, index) => (
                        <span key={index} className="skill-tag text-xs">
                          {tag}
                        </span>
                      ))}
                    </div>

                    {/* Mobile Table of Contents */}
                    <div className="lg:hidden mb-6">
                      <div className="bg-black/30 border border-green-400/30 rounded-lg p-4">
                        <div className="flex items-center space-x-2 mb-3">
                          <List className="w-4 h-4 text-green-300" />
                          <h3 className="text-sm font-semibold text-green-300">Table of Contents</h3>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {machine.sections.map((section, index) => (
                            <button
                              key={index}
                              onClick={() => scrollToSection(section.title)}
                              className="text-left text-sm py-1 px-2 rounded transition-colors text-green-400/70 hover:text-green-300 hover:bg-green-400/10 flex items-center space-x-2"
                            >
                              <ChevronRight className="w-3 h-3" />
                              <span>{section.title}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Machine Image */}
                    {machine.image && (
                      <div className="mt-6">
                        <div className="bg-black/30 border border-green-400/30 rounded-lg p-4">
                          <div className="flex items-center space-x-2 mb-3">
                            <ImageIcon className="w-4 h-4 text-green-300" />
                            <span className="text-sm text-green-300">Machine Screenshot</span>
                          </div>
                          <img
                            src={machine.image || "/placeholder.svg"}
                            alt={`${machine.name} HTB Machine`}
                            className="w-full rounded border border-green-400/20"
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Writeup Content */}
                  <div className="space-y-8">
                    {machine.sections.map((section, index) => (
                      <div key={index} className="space-y-4">
                        <h2
                          id={section.title.toLowerCase().replace(/\s+/g, "-")}
                          className="text-xl font-semibold text-green-300 border-b border-green-400/30 pb-2 scroll-mt-8"
                        >
                          {section.title}
                        </h2>

                        {section.content.map((item, itemIndex) => (
                          <div key={itemIndex} className="space-y-3">
                            {item.type === "text" && (
                              <p className="text-green-400/90 leading-relaxed">{item.content}</p>
                            )}

                            {item.type === "code" && (
                              <div className="relative">
                                <div className="bg-black/50 border border-green-400/30 rounded p-4 overflow-x-auto">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-xs text-green-400/70">{item.language}</span>
                                    <button
                                      onClick={() => copyToClipboard(item.content, `code-${index}-${itemIndex}`)}
                                      className="flex items-center space-x-1 text-xs hover:text-green-300 transition-colors"
                                    >
                                      {copied === `code-${index}-${itemIndex}` ? (
                                        <Check className="w-3 h-3" />
                                      ) : (
                                        <Copy className="w-3 h-3" />
                                      )}
                                      <span>{copied === `code-${index}-${itemIndex}` ? "Copied!" : "Copy"}</span>
                                    </button>
                                  </div>
                                  <pre className="text-green-300 text-sm">
                                    <code>{item.content}</code>
                                  </pre>
                                </div>
                              </div>
                            )}

                            {item.type === "list" && (
                              <ul className="space-y-2 ml-4">
                                {item.items.map((listItem, listIndex) => (
                                  <li key={listIndex} className="text-green-400/90 flex items-start">
                                    <span className="text-green-300 mr-2">•</span>
                                    <span>{listItem}</span>
                                  </li>
                                ))}
                              </ul>
                            )}

                            {item.type === "info" && (
                              <div className="bg-blue-400/10 border border-blue-400/30 rounded p-4">
                                <div className="flex items-start space-x-2">
                                  <span className="text-blue-400 font-bold">ℹ️</span>
                                  <p className="text-blue-400/90">{item.content}</p>
                                </div>
                              </div>
                            )}

                            {item.type === "warning" && (
                              <div className="bg-yellow-400/10 border border-yellow-400/30 rounded p-4">
                                <div className="flex items-start space-x-2">
                                  <span className="text-yellow-400 font-bold">⚠️</span>
                                  <p className="text-yellow-400/90">{item.content}</p>
                                </div>
                              </div>
                            )}

                            {item.type === "success" && (
                              <div className="bg-green-400/10 border border-green-400/30 rounded p-4">
                                <div className="flex items-start space-x-2">
                                  <span className="text-green-400 font-bold">✅</span>
                                  <p className="text-green-400/90">{item.content}</p>
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>

                  {/* Footer */}
                  <div className="border-t border-green-400/30 pt-6 mt-8">
                    <div className="flex items-center justify-between">
                      <div className="text-sm text-green-400/70">
                        Machine: {machine.name} | Difficulty: {machine.difficulty}
                      </div>
                      <div className="flex items-center space-x-4">
                        <Link href="/htb" className="text-sm hover:text-green-300 transition-colors">
                          ← Back to HTB Portfolio
                        </Link>
                      </div>
                    </div>
                  </div>

                  <div className="text-center mt-8">
                    <p className="text-green-400/70 text-sm">
                      root@wepliep:~/htb/{params.slug}$ echo "Machine pwned successfully!"
                    </p>
                  </div>
                </div>
              )}
            </div>
          </main>
        </div>
      </div>
    </div>
  )
}
