UniElect Voting Management System
📋 Overview
A comprehensive, secure, and scalable voting management system designed for university elections. Built with Next.js, TypeScript, Express.js, Tailwind CSS, Shadcn UI, and Prisma with Neon PostgreSQL.
🚀 Features
For Voters (Students)

Secure Authentication: Login using university student ID
Real-time Election Access: View active elections based on eligibility
Intuitive Voting Interface: Cast votes with confirmation steps
Vote Verification: Receive cryptographic proof of vote submission
Election Results: View live results after voting closes
Vote History: Access personal voting participation records

For Administrators

Comprehensive Dashboard: Real-time analytics and monitoring
Election Management: Create, schedule, and manage multiple elections
Candidate Management: Add, edit, and verify candidates
Voter Management: Import, verify, and manage eligible voters
Real-time Monitoring: Track voting progress and participation rates
Results Management: Generate detailed reports and analytics
Audit Logs: Complete system activity tracking
Security Controls: Manage access levels and permissions

🏗️ System Architecture
┌─────────────────────────────────────────────────────────────┐
│                         Frontend (Next.js)                   │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │   Public    │  │    Voter     │  │     Admin       │   │
│  │   Pages     │  │   Dashboard  │  │    Dashboard    │   │
│  └─────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ REST API / WebSocket
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Backend (Express.js)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │ Auth Service │  │ Vote Service │  │ Admin Service  │   │
│  └──────────────┘  └──────────────┘  └────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Prisma ORM
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Neon PostgreSQL Database                  │
└─────────────────────────────────────────────────────────────┘
📁 Complete File Structure
unielect-voting-system/
├── frontend/                          # Next.js Frontend Application
│   ├── app/                          # App Router Directory
│   │   ├── (auth)/                   # Authentication Routes Group
│   │   │   ├── login/
│   │   │   │   └── page.tsx
│   │   │   ├── register/
│   │   │   │   └── page.tsx
│   │   │   └── layout.tsx
│   │   ├── (voter)/                  # Voter Routes Group
│   │   │   ├── dashboard/
│   │   │   │   └── page.tsx
│   │   │   ├── elections/
│   │   │   │   ├── [id]/
│   │   │   │   │   └── page.tsx
│   │   │   │   └── page.tsx
│   │   │   ├── vote/
│   │   │   │   └── [electionId]/
│   │   │   │       └── page.tsx
│   │   │   ├── results/
│   │   │   │   └── [id]/
│   │   │   │       └── page.tsx
│   │   │   ├── history/
│   │   │   │   └── page.tsx
│   │   │   └── layout.tsx
│   │   ├── admin/                    # Admin Routes
│   │   │   ├── dashboard/
│   │   │   │   └── page.tsx
│   │   │   ├── elections/
│   │   │   │   ├── create/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── [id]/
│   │   │   │   │   ├── edit/
│   │   │   │   │   │   └── page.tsx
│   │   │   │   │   ├── candidates/
│   │   │   │   │   │   └── page.tsx
│   │   │   │   │   ├── voters/
│   │   │   │   │   │   └── page.tsx
│   │   │   │   │   └── page.tsx
│   │   │   │   └── page.tsx
│   │   │   ├── candidates/
│   │   │   │   ├── create/
│   │   │   │   │   └── page.tsx
│   │   │   │   └── page.tsx
│   │   │   ├── voters/
│   │   │   │   ├── import/
│   │   │   │   │   └── page.tsx
│   │   │   │   └── page.tsx
│   │   │   ├── results/
│   │   │   │   └── page.tsx
│   │   │   ├── reports/
│   │   │   │   └── page.tsx
│   │   │   ├── audit/
│   │   │   │   └── page.tsx
│   │   │   ├── settings/
│   │   │   │   └── page.tsx
│   │   │   └── layout.tsx
│   │   ├── api/                      # API Routes
│   │   │   ├── auth/
│   │   │   │   └── [...nextauth]/
│   │   │   │       └── route.ts
│   │   │   └── revalidate/
│   │   │       └── route.ts
│   │   ├── layout.tsx                # Root Layout
│   │   ├── globals.css               # Global Styles
│   │   └── page.tsx                  # Landing Page
│   ├── components/                   # Reusable Components
│   │   ├── ui/                      # Shadcn UI Components
│   │   │   ├── button.tsx
│   │   │   ├── card.tsx
│   │   │   ├── dialog.tsx
│   │   │   ├── form.tsx
│   │   │   ├── input.tsx
│   │   │   ├── label.tsx
│   │   │   ├── select.tsx
│   │   │   ├── table.tsx
│   │   │   ├── tabs.tsx
│   │   │   ├── toast.tsx
│   │   │   ├── dropdown-menu.tsx
│   │   │   ├── alert.tsx
│   │   │   ├── badge.tsx
│   │   │   ├── progress.tsx
│   │   │   ├── skeleton.tsx
│   │   │   └── chart.tsx
│   │   ├── auth/                    # Authentication Components
│   │   │   ├── LoginForm.tsx
│   │   │   ├── RegisterForm.tsx
│   │   │   ├── AuthGuard.tsx
│   │   │   └── SessionProvider.tsx
│   │   ├── voter/                   # Voter Components
│   │   │   ├── ElectionCard.tsx
│   │   │   ├── CandidateCard.tsx
│   │   │   ├── VotingBallot.tsx
│   │   │   ├── VoteConfirmation.tsx
│   │   │   ├── VoteReceipt.tsx
│   │   │   └── ResultsChart.tsx
│   │   ├── admin/                   # Admin Components
│   │   │   ├── StatsCard.tsx
│   │   │   ├── ElectionForm.tsx
│   │   │   ├── CandidateForm.tsx
│   │   │   ├── VoterImport.tsx
│   │   │   ├── ElectionTable.tsx
│   │   │   ├── VoterTable.tsx
│   │   │   ├── AuditLog.tsx
│   │   │   └── ReportsGenerator.tsx
│   │   └── shared/                  # Shared Components
│   │       ├── Header.tsx
│   │       ├── Footer.tsx
│   │       ├── Sidebar.tsx
│   │       ├── LoadingSpinner.tsx
│   │       ├── ErrorBoundary.tsx
│   │       └── NotificationBell.tsx
│   ├── lib/                         # Utility Libraries
│   │   ├── api/                    # API Client Functions
│   │   │   ├── auth.ts
│   │   │   ├── elections.ts
│   │   │   ├── candidates.ts
│   │   │   ├── votes.ts
│   │   │   ├── results.ts
│   │   │   └── admin.ts
│   │   ├── hooks/                  # Custom React Hooks
│   │   │   ├── useAuth.ts
│   │   │   ├── useElections.ts
│   │   │   ├── useVoting.ts
│   │   │   ├── useResults.ts
│   │   │   ├── useWebSocket.ts
│   │   │   └── useNotifications.ts
│   │   ├── utils/                  # Utility Functions
│   │   │   ├── validators.ts
│   │   │   ├── formatters.ts
│   │   │   ├── crypto.ts
│   │   │   └── dates.ts
│   │   ├── constants.ts
│   │   └── types.ts                # TypeScript Types
│   ├── public/                     # Static Assets
│   │   ├── images/
│   │   └── fonts/
│   ├── styles/                     # Additional Styles
│   ├── .env.local
│   ├── .eslintrc.json
│   ├── next.config.js
│   ├── package.json
│   ├── postcss.config.js
│   ├── tailwind.config.ts
│   └── tsconfig.json
│
├── backend/                         # Express.js Backend Application
│   ├── src/
│   │   ├── controllers/           # Request Handlers
│   │   │   ├── auth.controller.ts
│   │   │   ├── election.controller.ts
│   │   │   ├── candidate.controller.ts
│   │   │   ├── vote.controller.ts
│   │   │   ├── result.controller.ts
│   │   │   ├── voter.controller.ts
│   │   │   ├── admin.controller.ts
│   │   │   └── audit.controller.ts
│   │   ├── services/              # Business Logic
│   │   │   ├── auth.service.ts
│   │   │   ├── election.service.ts
│   │   │   ├── candidate.service.ts
│   │   │   ├── vote.service.ts
│   │   │   ├── result.service.ts
│   │   │   ├── voter.service.ts
│   │   │   ├── admin.service.ts
│   │   │   ├── audit.service.ts
│   │   │   ├── notification.service.ts
│   │   │   └── crypto.service.ts
│   │   ├── routes/                # API Routes
│   │   │   ├── auth.routes.ts
│   │   │   ├── election.routes.ts
│   │   │   ├── candidate.routes.ts
│   │   │   ├── vote.routes.ts
│   │   │   ├── result.routes.ts
│   │   │   ├── voter.routes.ts
│   │   │   ├── admin.routes.ts
│   │   │   └── index.ts
│   │   ├── middleware/            # Express Middleware
│   │   │   ├── auth.middleware.ts
│   │   │   ├── validation.middleware.ts
│   │   │   ├── error.middleware.ts
│   │   │   ├── rateLimit.middleware.ts
│   │   │   ├── cors.middleware.ts
│   │   │   └── logger.middleware.ts
│   │   ├── validators/            # Request Validators
│   │   │   ├── auth.validator.ts
│   │   │   ├── election.validator.ts
│   │   │   ├── candidate.validator.ts
│   │   │   ├── vote.validator.ts
│   │   │   └── voter.validator.ts
│   │   ├── utils/                 # Utility Functions
│   │   │   ├── encryption.ts
│   │   │   ├── hashing.ts
│   │   │   ├── jwt.ts
│   │   │   ├── logger.ts
│   │   │   ├── email.ts
│   │   │   ├── sms.ts
│   │   │   └── helpers.ts
│   │   ├── types/                 # TypeScript Type Definitions
│   │   │   ├── auth.types.ts
│   │   │   ├── election.types.ts
│   │   │   ├── vote.types.ts
│   │   │   ├── express.d.ts
│   │   │   └── index.ts
│   │   ├── config/                # Configuration Files
│   │   │   ├── database.ts
│   │   │   ├── redis.ts
│   │   │   ├── websocket.ts
│   │   │   └── index.ts
│   │   ├── websocket/             # WebSocket Handlers
│   │   │   ├── handlers.ts
│   │   │   └── events.ts
│   │   ├── jobs/                  # Background Jobs
│   │   │   ├── election.jobs.ts
│   │   │   ├── notification.jobs.ts
│   │   │   └── cleanup.jobs.ts
│   │   ├── app.ts                 # Express App Setup
│   │   └── server.ts              # Server Entry Point
│   ├── prisma/
│   │   ├── schema.prisma          # Database Schema
│   │   ├── seed.ts                # Database Seeder
│   │   └── migrations/            # Database Migrations
│   ├── tests/                     # Test Files
│   │   ├── unit/
│   │   ├── integration/
│   │   └── e2e/
│   ├── .env
│   ├── .env.example
│   ├── .eslintrc.json
│   ├── jest.config.js
│   ├── nodemon.json
│   ├── package.json
│   └── tsconfig.json
│
├── docker-compose.yml              # Docker Configuration
├── .gitignore
└── README.md