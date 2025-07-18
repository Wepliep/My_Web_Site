"use client"

import { useState } from "react"
import Link from "next/link"
import {
  Terminal,
  ArrowLeft,
  Target,
  Calendar,
  ExternalLink,
  Trophy,
  Star,
  Flag,
  Filter,
  Monitor,
  HardDrive,
  Server,
} from "lucide-react"

const htbStats = {
  rank: "Hacker",
  points: 1337,
  ownedMachines: 42,
}

const completedMachines = [
  {
    name: "Lame",
    os: "Linux",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-15",
    writeup: true,
    slug: "lame",
    tags: ["SMB", "CVE-2007-2447", "Samba"],
  },
  {
    name: "Legacy",
    os: "Windows",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-14",
    writeup: true,
    slug: "legacy",
    tags: ["MS08-067", "Buffer Overflow", "SMB"],
  },
  {
    name: "Blue",
    os: "Windows",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-13",
    writeup: true,
    slug: "blue",
    tags: ["MS17-010", "EternalBlue", "SMB"],
  },
  {
    name: "Netmon",
    os: "Windows",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-12",
    writeup: true,
    slug: "netmon",
    tags: ["PRTG", "FTP", "Credentials"],
  },
  {
    name: "Beep",
    os: "Linux",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-11",
    writeup: true,
    slug: "beep",
    tags: ["Elastix", "LFI", "FreePBX"],
  },
  {
    name: "Optimum",
    os: "Windows",
    difficulty: "Easy",
    points: 20,
    date: "2024-01-10",
    writeup: true,
    slug: "optimum",
    tags: ["HttpFileServer", "CVE-2014-6287", "Privilege Escalation"],
  },
]

export default function HTBPage() {
  const [selectedDifficulty, setSelectedDifficulty] = useState("All")
  const [selectedOS, setSelectedOS] = useState("All")

  const difficulties = ["All", "Easy", "Medium", "Hard", "Insane"]
  const operatingSystems = ["All", "Linux", "Windows", "Other"]

  const filteredMachines = completedMachines.filter((machine) => {
    const difficultyMatch = selectedDifficulty === "All" || machine.difficulty === selectedDifficulty
    const osMatch = selectedOS === "All" || machine.os === selectedOS
    return difficultyMatch && osMatch
  })

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Easy":
        return "text-green-400"
      case "Medium":
        return "text-yellow-400"
      case "Hard":
        return "text-orange-400"
      case "Insane":
        return "text-red-400"
      default:
        return "text-green-400"
    }
  }

  const getOSIcon = (os: string) => {
    switch (os) {
      case "Linux":
        return <Terminal className="w-4 h-4" />
      case "Windows":
        return <Monitor className="w-4 h-4" />
      case "Other":
        return <Server className="w-4 h-4" />
      default:
        return <HardDrive className="w-4 h-4" />
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
              <span className="ml-4 text-green-400/70">hackthebox.sh</span>
            </div>

            <div className="space-y-8">
              <div>
                <h1 className="text-3xl font-bold mb-4 text-green-300">HackTheBox Portfolio</h1>
                <p className="text-green-400/70 mb-6">Penetration testing skills through HTB challenges</p>
              </div>

              {/* Enhanced Stats with Icons */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <div className="stat-card text-center">
                  <div className="flex items-center justify-center mb-2">
                    <Trophy className="w-8 h-8 text-green-300" />
                  </div>
                  <div className="text-2xl font-bold text-green-300 mb-1">{htbStats.rank}</div>
                  <div className="text-sm text-green-400/70">Current Rank</div>
                </div>
                <div className="stat-card text-center">
                  <div className="flex items-center justify-center mb-2">
                    <Star className="w-8 h-8 text-green-300" />
                  </div>
                  <div className="text-2xl font-bold text-green-300 mb-1">{htbStats.points}</div>
                  <div className="text-sm text-green-400/70">Total Points</div>
                </div>
                <div className="stat-card text-center">
                  <div className="flex items-center justify-center mb-2">
                    <Target className="w-8 h-8 text-green-300" />
                  </div>
                  <div className="text-2xl font-bold text-green-300 mb-1">{htbStats.ownedMachines}</div>
                  <div className="text-sm text-green-400/70">Machines Owned</div>
                </div>
              </div>

              {/* Enhanced Filters with Icons */}
              <div className="flex flex-wrap gap-4 mb-6">
                <div className="flex flex-wrap gap-2 items-center">
                  <div className="flex items-center space-x-2">
                    <Filter className="w-4 h-4 text-green-300" />
                    <span className="text-sm text-green-300">Difficulty:</span>
                  </div>
                  {difficulties.map((difficulty) => (
                    <button
                      key={difficulty}
                      onClick={() => setSelectedDifficulty(difficulty)}
                      className={`px-3 py-1 rounded border text-sm transition-colors ${
                        selectedDifficulty === difficulty
                          ? "bg-green-400/20 border-green-400 text-green-300"
                          : "border-green-400/30 hover:border-green-400/50 hover:text-green-300"
                      }`}
                    >
                      {difficulty}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap gap-2 items-center">
                  <div className="flex items-center space-x-2">
                    <HardDrive className="w-4 h-4 text-green-300" />
                    <span className="text-sm text-green-300">OS:</span>
                  </div>
                  {operatingSystems.map((os) => (
                    <button
                      key={os}
                      onClick={() => setSelectedOS(os)}
                      className={`px-3 py-1 rounded border text-sm transition-colors flex items-center space-x-1 ${
                        selectedOS === os
                          ? "bg-green-400/20 border-green-400 text-green-300"
                          : "border-green-400/30 hover:border-green-400/50 hover:text-green-300"
                      }`}
                    >
                      {os !== "All" && getOSIcon(os)}
                      <span>{os}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Completed Machines */}
              <div>
                <div className="flex items-center space-x-2 mb-4">
                  <Flag className="w-5 h-5 text-green-300" />
                  <h2 className="text-xl font-semibold text-green-300">
                    Completed Machines ({filteredMachines.length})
                  </h2>
                </div>
                <div className="space-y-3">
                  {filteredMachines.map((machine, index) => (
                    <div key={index} className="project-card">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <Target className="w-5 h-5 text-green-300" />
                          <h3 className="text-lg font-semibold text-green-300">{machine.name}</h3>
                          <div className="flex items-center space-x-1">
                            {getOSIcon(machine.os)}
                            <span className="text-sm text-green-400/70">{machine.os}</span>
                          </div>
                          <span className={`text-sm font-semibold ${getDifficultyColor(machine.difficulty)}`}>
                            {machine.difficulty}
                          </span>
                        </div>
                        <div className="flex items-center space-x-4">
                          <div className="flex items-center space-x-1 text-sm text-green-400/70">
                            <Calendar className="w-4 h-4" />
                            <span>{machine.date}</span>
                          </div>
                          <div className="flex items-center space-x-1 text-sm font-semibold text-green-300">
                            <Star className="w-4 h-4" />
                            <span>{machine.points} pts</span>
                          </div>
                          {machine.writeup && (
                            <Link
                              href={`/htb/${machine.slug}`}
                              className="flex items-center space-x-1 text-sm hover:text-green-300 transition-colors"
                            >
                              <ExternalLink className="w-4 h-4" />
                              <span>Writeup</span>
                            </Link>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {machine.tags.map((tag, tagIndex) => (
                          <span key={tagIndex} className="skill-tag text-xs">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-8 text-center">
                <p className="text-green-400/70">root@wepliep:~/htb$ echo "Try Harder!"</p>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
