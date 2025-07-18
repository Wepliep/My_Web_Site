"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { Terminal, ChevronRight, Zap } from "lucide-react"

export default function HomePage() {
  const [displayText, setDisplayText] = useState("")
  const [currentIndex, setCurrentIndex] = useState(0)
  const [showCursor, setShowCursor] = useState(true)

  const welcomeMessage = "Welcome to my Matrix..."
  const subMessage = "root@wepliep:~$ whoami"

  useEffect(() => {
    if (currentIndex < welcomeMessage.length) {
      const timeout = setTimeout(() => {
        setDisplayText((prev) => prev + welcomeMessage[currentIndex])
        setCurrentIndex((prev) => prev + 1)
      }, 100)
      return () => clearTimeout(timeout)
    }
  }, [currentIndex, welcomeMessage])

  useEffect(() => {
    const cursorInterval = setInterval(() => {
      setShowCursor((prev) => !prev)
    }, 500)
    return () => clearInterval(cursorInterval)
  }, [])

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono relative overflow-hidden">
      {/* Scanlines effect */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="scanlines"></div>
      </div>

      {/* Matrix rain background */}
      <div className="matrix-bg"></div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <header className="border-b border-green-400/30 pb-4 mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Terminal className="w-6 h-6" />
              <span className="text-xl font-bold">Wepliep</span>
            </div>
            <nav className="hidden md:flex space-x-6">
              <Link href="/" className="hover:text-green-300 transition-colors">
                ~/home
              </Link>
              <Link href="/about" className="hover:text-green-300 transition-colors">
                ~/about
              </Link>
              <Link href="/projects" className="hover:text-green-300 transition-colors">
                ~/projects
              </Link>
              <Link href="/notes" className="hover:text-green-300 transition-colors">
                ~/notes
              </Link>
              <Link href="/htb" className="hover:text-green-300 transition-colors">
                ~/htb
              </Link>
            </nav>
          </div>
        </header>

        {/* Main Content */}
        <main className="flex flex-col items-center justify-center min-h-[60vh] text-center">
          <div className="terminal-window bg-black/50 border border-green-400/50 rounded-lg p-8 max-w-2xl w-full backdrop-blur-sm">
            <div className="flex items-center space-x-2 mb-4 text-sm">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="ml-4 text-green-400/70">root@wepliep</span>
            </div>

            <div className="text-left space-y-4">
              <div className="text-2xl md:text-3xl">
                {displayText}
                <span className={`${showCursor ? "opacity-100" : "opacity-0"} transition-opacity`}>_</span>
              </div>

              {currentIndex >= welcomeMessage.length && (
                <div className="space-y-2 animate-fade-in">
                  <div className="text-green-300">{subMessage}</div>
                  <div className="text-green-400">
                    <span className="text-green-300">Name:</span> Cybersecurity Enthusiast
                    <br />
                    <span className="text-green-300">Status:</span> Penetration Testing | Bug Hunting | CTF Player
                    <br />
                    <span className="text-green-300">Location:</span> The Digital Underground
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Navigation Cards */}
          {currentIndex >= welcomeMessage.length && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-12 w-full max-w-4xl animate-slide-up">
              <Link href="/about" className="nav-card group">
                <div className="flex flex-col items-center justify-center text-center h-full">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold mb-2">About Me</h3>
                    <p className="text-sm text-green-400/70">Learn about my journey</p>
                  </div>
                  <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>

              <Link href="/projects" className="nav-card group">
                <div className="flex flex-col items-center justify-center text-center h-full">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold mb-2">Projects</h3>
                    <p className="text-sm text-green-400/70">Cybersecurity tools & research</p>
                  </div>
                  <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>

              <Link href="/notes" className="nav-card group">
                <div className="flex flex-col items-center justify-center text-center h-full">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold mb-2">Knowledge Base</h3>
                    <p className="text-sm text-green-400/70">Notes & writeups</p>
                  </div>
                  <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>

              <Link href="/htb" className="nav-card group md:col-span-2 lg:col-span-1">
                <div className="flex flex-col items-center justify-center text-center h-full">
                  <div className="mb-4">
                    <h3 className="text-lg font-semibold mb-2 flex items-center justify-center">
                      <Zap className="w-5 h-5 mr-2" />
                      HackTheBox
                    </h3>
                    <p className="text-sm text-green-400/70">Portfolio & achievements</p>
                  </div>
                  <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>
            </div>
          )}
        </main>

        {/* Footer */}
        <footer className="mt-16 text-center text-green-400/50 text-sm">
          <p>root@wepliep:~$ echo "Stay curious, stay secure"</p>
        </footer>
      </div>
    </div>
  )
}
