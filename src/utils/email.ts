import nodemailer from 'nodemailer';
import { logger } from './logger';
import fs from 'fs/promises';
import path from 'path';
import handlebars from 'handlebars';
import QRCode from 'qrcode';

export interface EmailOptions {
  to: string | string[];
  subject: string;
  template?: string;
  data?: Record<string, any>;
  html?: string;
  text?: string;
  attachments?: Array<{
    filename: string;
    path?: string;
    content?: Buffer;
  }>;
}

export class EmailService {
  private static instance: EmailService;
  private transporter: nodemailer.Transporter;
  private templates: Map<string, handlebars.TemplateDelegate> = new Map();

  private constructor() {
    // Configure transporter using existing environment variables
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'localhost',
      port: parseInt(process.env.SMTP_PORT || '1025'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      } : undefined,
      ignoreTLS: process.env.NODE_ENV === 'development',
    });

    // Verify transporter configuration
    this.transporter.verify((error) => {
      if (error) {
        logger.error('Email transporter verification failed:', error);
      } else {
        logger.info('Email transporter is ready');
      }
    });

    // Load email templates
    this.loadTemplates();
  }

  public static getInstance(): EmailService {
    if (!EmailService.instance) {
      EmailService.instance = new EmailService();
    }
    return EmailService.instance;
  }

  /**
   * Load email templates
   */
  private async loadTemplates(): Promise<void> {
    const templateDir = path.join(process.cwd(), 'templates', 'emails');
    
    const templates = [
      'welcome',
      'email-verification',
      'password-reset',
      'election-started',
      'election-reminder',
      'vote-confirmation',
      'results-published',
      'candidate-approved',
      'candidate-rejected',
      'candidate-application-received',
      'election-deadline-reminder',
      'election-eligibility',
      'security-alert',
      'system-maintenance',
      'daily-digest',
      'admin-notification',
    ];

    for (const templateName of templates) {
      try {
        const templatePath = path.join(templateDir, `${templateName}.hbs`);
        const templateContent = await fs.readFile(templatePath, 'utf-8').catch(() => this.getDefaultTemplate(templateName));
        const compiled = handlebars.compile(templateContent);
        this.templates.set(templateName, compiled);
      } catch (error) {
        logger.warn(`Failed to load email template: ${templateName}`);
      }
    }
  }

  /**
   * Get default template content
   */
  private getDefaultTemplate(templateName: string): string {
    const templates: Record<string, string> = {
      'welcome': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #2563eb;">Welcome to UniElect Voting System</h1>
          <p>Dear {{firstName}},</p>
          <p>Your account has been successfully created for the UniElect voting platform.</p>
          <p><strong>Student ID:</strong> {{studentId}}</p>
          <p>Please verify your email address to start participating in elections.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #f3f4f6; border-radius: 5px;">
            <p style="margin: 0;"><strong>Next Steps:</strong></p>
            <ul>
              <li>Verify your email address</li>
              <li>Complete your profile setup</li>
              <li>Browse available elections</li>
            </ul>
          </div>
          <p>If you have any questions, please contact our support team.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'email-verification': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #2563eb;">Verify Your Email Address</h1>
          <p>Dear {{firstName}},</p>
          <p>Please verify your email address to activate your UniElect account.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{verificationUrl}}" style="background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email Address</a>
          </div>
          <p>Alternatively, you can use this verification code: <strong>{{verificationCode}}</strong></p>
          <p>This verification link will expire in 24 hours for security purposes.</p>
          <p>If you did not create this account, please ignore this email.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'password-reset': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #2563eb;">Password Reset Request</h1>
          <p>Dear {{firstName}},</p>
          <p>We received a request to reset your password for your UniElect account.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{resetUrl}}" style="background-color: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
          </div>
          <p>This link will expire in 1 hour for security purposes.</p>
          <p>If you did not request this password reset, please ignore this email and your password will remain unchanged.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'election-started': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #059669;">Election Now Open for Voting</h1>
          <p>Dear {{firstName}},</p>
          <p>The election <strong>"{{electionTitle}}"</strong> is now open and ready for your participation.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #f0fdf4; border-left: 4px solid #059669; border-radius: 5px;">
            <p style="margin: 0;"><strong>Election Details:</strong></p>
            <p>Title: {{electionTitle}}</p>
            <p>Voting Period Ends: {{endDate}}</p>
            <p>Your Voice Matters: Cast your vote and make a difference</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{voteUrl}}" style="background-color: #059669; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Cast Your Vote Now</a>
          </div>
          <p>Please ensure you vote before the deadline. Every vote counts in shaping our community's future.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'vote-confirmation': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #059669;">Vote Successfully Recorded</h1>
          <p>Dear {{firstName}},</p>
          <p>Your vote has been successfully recorded and secured in our system.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #f0fdf4; border-radius: 5px;">
            <p style="margin: 0;"><strong>Vote Details:</strong></p>
            <p>Election: {{electionTitle}}</p>
            <p>Timestamp: {{timestamp}}</p>
            <p>Verification Code: <code style="background-color: #e5e7eb; padding: 2px 4px; border-radius: 3px;">{{verificationCode}}</code></p>
            <p>Vote Hash: <code style="background-color: #e5e7eb; padding: 2px 4px; border-radius: 3px; font-size: 12px;">{{voteHash}}</code></p>
          </div>
          <p>Please keep this confirmation for your records. You can use the verification code to verify your vote was counted.</p>
          <p>Thank you for participating in the democratic process.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'results-published': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #7c3aed;">Election Results Available</h1>
          <p>Dear {{firstName}},</p>
          <p>The results for <strong>"{{electionTitle}}"</strong> have been published and are now available for viewing.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{resultsUrl}}" style="background-color: #7c3aed; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">View Election Results</a>
          </div>
          <p>Thank you for your participation in this democratic process. Your vote helped shape these results.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'candidate-approved': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #059669;">Candidate Application Approved</h1>
          <p>Dear {{firstName}},</p>
          <p>Congratulations! Your application to be a candidate for <strong>"{{electionTitle}}"</strong> has been approved.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #f0fdf4; border-left: 4px solid #059669; border-radius: 5px;">
            <p style="margin: 0;"><strong>Campaign Details:</strong></p>
            <p>Election: {{electionTitle}}</p>
            <p>Position: {{position}}</p>
            <p>Status: Approved and Active</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #059669; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Manage Your Campaign</a>
          </div>
          <p>You can now start your campaign activities. Best of luck with your candidacy!</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'candidate-rejected': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #dc2626;">Candidate Application Requires Revision</h1>
          <p>Dear {{firstName}},</p>
          <p>Your application to be a candidate for <strong>"{{electionTitle}}"</strong> requires some revisions before approval.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #fef2f2; border-left: 4px solid #dc2626; border-radius: 5px;">
            <p style="margin: 0;"><strong>Feedback:</strong></p>
            <p>{{reason}}</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Revise Application</a>
          </div>
          <p>Please review the feedback and resubmit your application with the necessary corrections.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'candidate-application-received': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #2563eb;">New Candidate Application Received</h1>
          <p>Dear Administrator,</p>
          <p>A new candidate application has been submitted and requires your review.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #eff6ff; border-left: 4px solid #2563eb; border-radius: 5px;">
            <p style="margin: 0;"><strong>Application Details:</strong></p>
            <p>Candidate: {{candidateName}}</p>
            <p>Student ID: {{studentId}}</p>
            <p>Election: {{electionTitle}}</p>
            <p>Position: {{position}}</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Review Application</a>
          </div>
          <p>Please review this application at your earliest convenience.</p>
          <p>Best regards,<br>UniElect System</p>
        </div>
      `,
      'election-deadline-reminder': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #f59e0b;">Voting Deadline Approaching</h1>
          <p>Dear {{firstName}},</p>
          <p>This is a reminder that voting for <strong>"{{electionTitle}}"</strong> will close soon.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #fffbeb; border-left: 4px solid #f59e0b; border-radius: 5px;">
            <p style="margin: 0;"><strong>Time Remaining:</strong></p>
            <p>{{timeRemaining}} until voting closes</p>
            <p>Don't miss your chance to make your voice heard!</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #f59e0b; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Vote Now</a>
          </div>
          <p>Cast your vote before the deadline to ensure your participation is counted.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'election-eligibility': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #2563eb;">You're Eligible for New Election</h1>
          <p>Dear {{firstName}},</p>
          <p>A new election <strong>"{{electionTitle}}"</strong> is available and you are eligible to participate.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #eff6ff; border-left: 4px solid #2563eb; border-radius: 5px;">
            <p style="margin: 0;"><strong>Election Information:</strong></p>
            <p>Title: {{electionTitle}}</p>
            <p>Start Date: {{startDate}}</p>
            <p>End Date: {{endDate}}</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Learn More</a>
          </div>
          <p>Review the candidates and prepare to cast your vote when voting opens.</p>
          <p>Best regards,<br>UniElect Team</p>
        </div>
      `,
      'security-alert': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #dc2626;">Security Alert</h1>
          <p>Dear Administrator,</p>
          <p>A security event has been detected in the UniElect system that requires your attention.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #fef2f2; border-left: 4px solid #dc2626; border-radius: 5px;">
            <p style="margin: 0;"><strong>Security Event Details:</strong></p>
            <p>Event Type: {{eventType}}</p>
            <p>Severity: {{severity}}</p>
            <p>Timestamp: {{timestamp}}</p>
            <p>Details: {{details}}</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Review Security Event</a>
          </div>
          <p>Please investigate this event promptly to ensure system security.</p>
          <p>Best regards,<br>UniElect Security System</p>
        </div>
      `,
      'system-maintenance': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #6b7280;">System Maintenance Notification</h1>
          <p>Dear {{firstName}},</p>
          <p>We are scheduling system maintenance for the UniElect platform.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #f9fafb; border-left: 4px solid #6b7280; border-radius: 5px;">
            <p style="margin: 0;"><strong>Maintenance Details:</strong></p>
            <p>Title: {{title}}</p>
            <p>Description: {{message}}</p>
            {{#if scheduledTime}}<p>Scheduled Time: {{scheduledTime}}</p>{{/if}}
          </div>
          <p>During this time, the system may be temporarily unavailable. We apologize for any inconvenience.</p>
          <p>Best regards,<br>UniElect Technical Team</p>
        </div>
      `,
      'daily-digest': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #2563eb;">Daily System Digest</h1>
          <p>Dear Administrator,</p>
          <p>Here is your daily summary of UniElect system activity for {{date}}.</p>
          <div style="margin: 20px 0; padding: 15px; background-color: #eff6ff; border-radius: 5px;">
            <h3 style="margin-top: 0;">Activity Summary</h3>
            <p><strong>New Users:</strong> {{stats.newUsers}}</p>
            <p><strong>New Candidates:</strong> {{stats.newCandidates}}</p>
            <p><strong>Active Elections:</strong> {{stats.activeElections}}</p>
            <p><strong>Votes Cast:</strong> {{stats.totalVotes}}</p>
            <p><strong>Security Events:</strong> {{stats.securityEvents}}</p>
            <p><strong>System Notifications:</strong> {{stats.systemNotifications}}</p>
          </div>
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">View Dashboard</a>
          </div>
          <p>Best regards,<br>UniElect System</p>
        </div>
      `,
      'admin-notification': `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h1 style="color: #2563eb;">{{title}}</h1>
          <p>Dear Administrator,</p>
          <p>{{message}}</p>
          {{#if actionUrl}}
          <div style="text-align: center; margin: 30px 0;">
            <a href="{{actionUrl}}" style="background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Take Action</a>
          </div>
          {{/if}}
          <p>Best regards,<br>UniElect System</p>
        </div>
      `,
    };

    return templates[templateName] || '<p>{{content}}</p>';
  }

  /**
   * Send email
   */
  public async sendEmail(options: EmailOptions): Promise<boolean> {
    try {
      const { to, subject, template, data, html, text, attachments } = options;

      let emailHtml = html;
      let emailText = text;

      // Use template if provided
      if (template && this.templates.has(template)) {
        const compiledTemplate = this.templates.get(template)!;
        emailHtml = compiledTemplate(data || {});
      }

      // Prepare email options
      const mailOptions: nodemailer.SendMailOptions = {
        from: process.env.FROM_EMAIL || 'UniElect Voting System <noreply@unielect.com>',
        to: Array.isArray(to) ? to.join(', ') : to,
        subject,
        html: emailHtml,
        text: emailText || this.htmlToText(emailHtml || ''),
        attachments,
      };

      // Send email
      const info = await this.transporter.sendMail(mailOptions);
      
      logger.info('Email sent successfully', {
        messageId: info.messageId,
        to,
        subject,
      });

      return true;
    } catch (error) {
      logger.error('Failed to send email:', error);
      return false;
    }
  }

  /**
   * Send welcome email
   */
  public async sendWelcomeEmail(
    user: {
      email: string;
      firstName: string;
      studentId: string;
    }
  ): Promise<boolean> {
    return this.sendEmail({
      to: user.email,
      subject: 'Welcome to JKUAT Voting System',
      template: 'welcome',
      data: user,
    });
  }

  /**
   * Send email verification
   */
  public async sendVerificationEmail(
    user: {
      email: string;
      firstName: string;
    },
    verificationUrl: string,
    verificationCode: string
  ): Promise<boolean> {
    return this.sendEmail({
      to: user.email,
      subject: 'Verify Your Email - JKUAT Voting System',
      template: 'email-verification',
      data: {
        ...user,
        verificationUrl,
        verificationCode,
      },
    });
  }

  /**
   * Send password reset email
   */
  public async sendPasswordResetEmail(
    user: {
      email: string;
      firstName: string;
    },
    resetUrl: string
  ): Promise<boolean> {
    return this.sendEmail({
      to: user.email,
      subject: 'Password Reset Request - JKUAT Voting System',
      template: 'password-reset',
      data: {
        ...user,
        resetUrl,
      },
    });
  }

  /**
   * Send election notification
   */
  public async sendElectionNotification(
    users: Array<{ email: string; firstName: string }>,
    election: {
      title: string;
      endDate: string;
    },
    type: 'started' | 'reminder' | 'ending'
  ): Promise<void> {
    const subject = type === 'started' 
      ? `Election Started: ${election.title}`
      : type === 'reminder'
      ? `Reminder: Vote in ${election.title}`
      : `Last Chance: ${election.title} Ending Soon`;

    const template = type === 'started' ? 'election-started' : 'election-reminder';

    // Send in batches to avoid overwhelming the server
    const batchSize = 50;
    for (let i = 0; i < users.length; i += batchSize) {
      const batch = users.slice(i, i + batchSize);
      const emails = batch.map(u => u.email);
      
      await this.sendEmail({
        to: emails,
        subject,
        template,
        data: {
          ...election,
          voteUrl: `${process.env.FRONTEND_URL}/elections/${election.title}/vote`,
        },
      });

      // Small delay between batches
      if (i + batchSize < users.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }

  /**
   * Send vote confirmation
   */
  public async sendVoteConfirmation(
    user: {
      email: string;
      firstName: string;
    },
    voteDetails: {
      electionTitle: string;
      verificationCode: string;
      voteHash: string;
      timestamp: string;
    }
  ): Promise<boolean> {
    return this.sendEmail({
      to: user.email,
      subject: `Vote Confirmation - ${voteDetails.electionTitle}`,
      template: 'vote-confirmation',
      data: {
        ...user,
        ...voteDetails,
      },
      attachments: [
        {
          filename: 'vote-receipt.pdf',
          content: await this.generateVoteReceipt(voteDetails),
        },
      ],
    });
  }

  /**
   * Generate vote receipt PDF
   */
  private async generateVoteReceipt(voteDetails: any): Promise<Buffer> {
    const PDFDocument = require('pdfkit');
    const doc = new PDFDocument({
      size: 'A4',
      margin: 50,
      info: {
        Title: 'Vote Receipt',
        Author: 'JKUAT Voting System',
        Subject: 'Official Vote Receipt',
      }
    });

    const buffers: Buffer[] = [];
    doc.on('data', buffers.push.bind(buffers));

    // Generate QR Code first (before the Promise)
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${voteDetails.verificationCode}`;
    const qrCodeDataUrl = await QRCode.toDataURL(verificationUrl, {
      width: 100,
      margin: 1,
    });

    return new Promise((resolve) => {
      doc.on('end', () => {
        const pdfData = Buffer.concat(buffers);
        resolve(pdfData);
      });

      // Header with logo placeholder
      doc.fontSize(20)
         .font('Helvetica-Bold')
         .text('JKUAT VOTING SYSTEM', { align: 'center' });

      doc.fontSize(16)
         .text('OFFICIAL VOTE RECEIPT', { align: 'center' });

      doc.moveDown(2);

      // Receipt border
      doc.rect(50, 150, 500, 400).stroke();

      // Receipt content
      doc.fontSize(12)
         .font('Helvetica')
         .text('RECEIPT DETAILS', 70, 170, { underline: true });

      doc.moveDown();

      // Vote details
      const details = [
        { label: 'Election', value: voteDetails.electionTitle },
        { label: 'Date & Time', value: voteDetails.timestamp },
        { label: 'Verification Code', value: voteDetails.verificationCode },
        { label: 'Vote Hash', value: voteDetails.voteHash },
        { label: 'Status', value: 'Successfully Recorded' }
      ];

      let yPosition = 210;
      details.forEach(detail => {
        doc.font('Helvetica-Bold')
           .text(`${detail.label}:`, 70, yPosition, { continued: true })
           .font('Helvetica')
           .text(` ${detail.value}`, { width: 400 });
        yPosition += 30;
      });

      // Convert data URL to buffer and add to PDF
      const qrCodeImage = qrCodeDataUrl.replace(/^data:image\/png;base64,/, '');
      doc.image(Buffer.from(qrCodeImage, 'base64'), 250, 380, { width: 100, height: 100 });

      doc.fontSize(10)
         .text('Scan QR Code to Verify', 240, 490, { width: 120, align: 'center' });

      // Footer
      doc.fontSize(10)
         .font('Helvetica-Oblique')
         .text('This is an official receipt from JKUAT Voting System', 50, 580, { align: 'center' });

      doc.text('Keep this receipt for your records', { align: 'center' });

      doc.fontSize(8)
         .text(`Generated on ${new Date().toLocaleString()}`, 50, 620, { align: 'center' });

      // Security notice
      doc.rect(50, 650, 500, 60).stroke();
      doc.fontSize(8)
         .font('Helvetica')
         .text('SECURITY NOTICE: This receipt contains cryptographic proof of your vote.', 60, 660);
      doc.text('Your vote is encrypted and anonymous. Only you can verify your vote using the verification code.', 60, 675);
      doc.text('Report any discrepancies to: voting-support@jkuat.ac.ke', 60, 690);

      doc.end();
    });
  }

  /**
   * Convert HTML to plain text
   */
  private htmlToText(html: string): string {
    return html
      .replace(/<style[^>]*>.*?<\/style>/gs, '')
      .replace(/<script[^>]*>.*?<\/script>/gs, '')
      .replace(/<[^>]+>/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Send candidate approval email
   */
  public async sendCandidateApprovalEmail(
    candidate: {
      email: string;
      firstName: string;
      lastName: string;
    },
    election: {
      title: string;
      id: string;
    },
    position: string
  ): Promise<boolean> {
    return this.sendEmail({
      to: candidate.email,
      subject: `Application Approved - ${election.title}`,
      template: 'candidate-approved',
      data: {
        firstName: candidate.firstName,
        electionTitle: election.title,
        position,
        actionUrl: `${process.env.FRONTEND_URL}/elections/${election.id}/candidate-dashboard`,
      },
    });
  }

  /**
   * Send candidate rejection email
   */
  public async sendCandidateRejectionEmail(
    candidate: {
      email: string;
      firstName: string;
      lastName: string;
    },
    election: {
      title: string;
      id: string;
    },
    reason: string
  ): Promise<boolean> {
    return this.sendEmail({
      to: candidate.email,
      subject: `Application Update - ${election.title}`,
      template: 'candidate-rejected',
      data: {
        firstName: candidate.firstName,
        electionTitle: election.title,
        reason,
        actionUrl: `${process.env.FRONTEND_URL}/elections/${election.id}/apply`,
      },
    });
  }

  /**
   * Send new candidate application notification to moderators
   */
  public async sendCandidateApplicationNotification(
    moderators: Array<{ email: string; firstName: string }>,
    candidate: {
      firstName: string;
      lastName: string;
      studentId: string;
    },
    election: {
      title: string;
      id: string;
    },
    position: string,
    candidateId: string
  ): Promise<void> {
    const emails = moderators.map(m => m.email);

    await this.sendEmail({
      to: emails,
      subject: `New Candidate Application - ${election.title}`,
      template: 'candidate-application-received',
      data: {
        candidateName: `${candidate.firstName} ${candidate.lastName}`,
        studentId: candidate.studentId,
        electionTitle: election.title,
        position,
        actionUrl: `${process.env.FRONTEND_URL}/admin/candidates/${candidateId}/review`,
      },
    });
  }

  /**
   * Send election deadline reminder
   */
  public async sendElectionDeadlineReminder(
    voters: Array<{ email: string; firstName: string }>,
    election: {
      title: string;
      id: string;
    },
    hoursRemaining: number
  ): Promise<void> {
    const timeText = hoursRemaining < 24
      ? `${hoursRemaining} hours`
      : `${Math.floor(hoursRemaining / 24)} days`;

    const batchSize = 50;
    for (let i = 0; i < voters.length; i += batchSize) {
      const batch = voters.slice(i, i + batchSize);
      const emails = batch.map(v => v.email);

      await this.sendEmail({
        to: emails,
        subject: `Voting Deadline Reminder - ${election.title}`,
        template: 'election-deadline-reminder',
        data: {
          electionTitle: election.title,
          timeRemaining: timeText,
          actionUrl: `${process.env.FRONTEND_URL}/elections/${election.id}/vote`,
        },
      });

      // Rate limiting
      if (i + batchSize < voters.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }

  /**
   * Send election eligibility notification
   */
  public async sendElectionEligibilityNotification(
    voters: Array<{ email: string; firstName: string }>,
    election: {
      title: string;
      id: string;
      startDate?: Date;
      endDate?: Date;
    }
  ): Promise<void> {
    const batchSize = 50;
    for (let i = 0; i < voters.length; i += batchSize) {
      const batch = voters.slice(i, i + batchSize);
      const emails = batch.map(v => v.email);

      await this.sendEmail({
        to: emails,
        subject: `New Election Available - ${election.title}`,
        template: 'election-eligibility',
        data: {
          electionTitle: election.title,
          startDate: election.startDate?.toLocaleDateString(),
          endDate: election.endDate?.toLocaleDateString(),
          actionUrl: `${process.env.FRONTEND_URL}/elections/${election.id}`,
        },
      });

      // Rate limiting
      if (i + batchSize < voters.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }

  /**
   * Send security alert to admins
   */
  public async sendSecurityAlertEmail(
    admins: Array<{ email: string; firstName: string }>,
    eventType: string,
    details: any,
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  ): Promise<void> {
    const emails = admins.map(a => a.email);

    await this.sendEmail({
      to: emails,
      subject: `Security Alert - ${eventType} (${severity})`,
      template: 'security-alert',
      data: {
        eventType,
        severity,
        details: JSON.stringify(details, null, 2),
        timestamp: new Date().toLocaleString(),
        actionUrl: `${process.env.FRONTEND_URL}/admin/security/events`,
      },
    });
  }

  /**
   * Send system maintenance notification
   */
  public async sendSystemMaintenanceEmail(
    recipients: Array<{ email: string; firstName: string }>,
    title: string,
    message: string,
    scheduledTime?: Date
  ): Promise<void> {
    const emails = recipients.map(r => r.email);

    await this.sendEmail({
      to: emails,
      subject: `System Maintenance - ${title}`,
      template: 'system-maintenance',
      data: {
        title,
        message,
        scheduledTime: scheduledTime?.toLocaleString(),
        actionUrl: `${process.env.FRONTEND_URL}/admin/system/maintenance`,
      },
    });
  }

  /**
   * Send daily digest to admins
   */
  public async sendDailyDigestEmail(
    admins: Array<{ email: string; firstName: string }>,
    stats: {
      newUsers: number;
      newCandidates: number;
      activeElections: number;
      totalVotes: number;
      securityEvents: number;
      systemNotifications: number;
    },
    date: string
  ): Promise<void> {
    const emails = admins.map(a => a.email);

    await this.sendEmail({
      to: emails,
      subject: `Daily System Digest - ${date}`,
      template: 'daily-digest',
      data: {
        date,
        stats,
        actionUrl: `${process.env.FRONTEND_URL}/admin/dashboard`,
      },
    });
  }

  /**
   * Send enhanced vote confirmation with receipt
   */
  public async sendEnhancedVoteConfirmation(
    voter: {
      email: string;
      firstName: string;
    },
    voteDetails: {
      electionTitle: string;
      verificationCode: string;
      voteHash: string;
      timestamp: string;
      electionId: string;
    }
  ): Promise<boolean> {
    try {
      // Generate vote receipt PDF
      const receiptPdf = await this.generateVoteReceipt(voteDetails);

      return this.sendEmail({
        to: voter.email,
        subject: `Vote Confirmation - ${voteDetails.electionTitle}`,
        template: 'vote-confirmation',
        data: {
          firstName: voter.firstName,
          electionTitle: voteDetails.electionTitle,
          timestamp: voteDetails.timestamp,
          verificationCode: voteDetails.verificationCode,
          voteHash: voteDetails.voteHash,
        },
        attachments: [
          {
            filename: 'vote-receipt.pdf',
            content: receiptPdf,
          },
        ],
      });
    } catch (error) {
      logger.error('Failed to send enhanced vote confirmation:', error);
      // Fallback to simple email without PDF
      return this.sendEmail({
        to: voter.email,
        subject: `Vote Confirmation - ${voteDetails.electionTitle}`,
        template: 'vote-confirmation',
        data: {
          firstName: voter.firstName,
          electionTitle: voteDetails.electionTitle,
          timestamp: voteDetails.timestamp,
          verificationCode: voteDetails.verificationCode,
          voteHash: voteDetails.voteHash,
        },
      });
    }
  }

  /**
   * Send bulk emails
   */
  public async sendBulkEmail(
    recipients: Array<{ email: string; data?: Record<string, any> }>,
    subject: string,
    template: string
  ): Promise<void> {
    const batchSize = 100;
    let successCount = 0;
    let failCount = 0;

    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);

      const promises = batch.map(recipient =>
        this.sendEmail({
          to: recipient.email,
          subject,
          template,
          data: recipient.data,
        })
      );

      const results = await Promise.allSettled(promises);

      results.forEach(result => {
        if (result.status === 'fulfilled' && result.value) {
          successCount++;
        } else {
          failCount++;
        }
      });

      // Rate limiting
      if (i + batchSize < recipients.length) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    logger.info(`Bulk email completed: ${successCount} sent, ${failCount} failed`);
  }
}

// Export singleton instance
export const emailService = EmailService.getInstance();

export default emailService;