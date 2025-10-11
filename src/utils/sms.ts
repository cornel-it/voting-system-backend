import twilio from 'twilio';
import { logger } from './logger';

export interface SMSOptions {
  to: string | string[];
  message: string;
}

export class SMSService {
  private static instance: SMSService;
  private client: twilio.Twilio;
  private fromNumber: string;
  private isEnabled: boolean;

  private constructor() {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    this.fromNumber = process.env.TWILIO_PHONE_NUMBER || '';

    if (accountSid && authToken && this.fromNumber) {
      this.client = twilio(accountSid, authToken);
      this.isEnabled = true;
      logger.info('SMS service initialized successfully');
    } else {
      logger.warn('SMS service disabled: Missing Twilio credentials');
      this.isEnabled = false;
      // Create a dummy client for development
      this.client = {} as twilio.Twilio;
    }
  }

  public static getInstance(): SMSService {
    if (!SMSService.instance) {
      SMSService.instance = new SMSService();
    }
    return SMSService.instance;
  }

  /**
   * Send SMS message
   */
  public async sendSMS(options: SMSOptions): Promise<boolean> {
    if (!this.isEnabled) {
      logger.warn('SMS service is disabled');
      return false;
    }

    try {
      const { to, message } = options;
      const recipients = Array.isArray(to) ? to : [to];

      const results = await Promise.allSettled(
        recipients.map(async (recipient) => {
          // Format phone number (add country code if missing)
          const formattedNumber = this.formatPhoneNumber(recipient);
          
          const result = await this.client.messages.create({
            body: message,
            from: this.fromNumber,
            to: formattedNumber,
          });

          logger.info('SMS sent successfully', {
            sid: result.sid,
            to: formattedNumber,
            status: result.status,
          });

          return result;
        })
      );

      const successCount = results.filter(r => r.status === 'fulfilled').length;
      const failCount = results.filter(r => r.status === 'rejected').length;

      if (failCount > 0) {
        logger.warn(`SMS sending partially failed: ${successCount} sent, ${failCount} failed`);
      }

      return successCount > 0;
    } catch (error) {
      logger.error('Failed to send SMS:', error);
      return false;
    }
  }

  /**
   * Send OTP via SMS
   */
  public async sendOTP(phoneNumber: string, otp: string): Promise<boolean> {
    const message = `Your JKUAT Voting System verification code is: ${otp}. Valid for 10 minutes. Do not share this code.`;
    
    return this.sendSMS({
      to: phoneNumber,
      message,
    });
  }

  /**
   * Send voting notification
   */
  public async sendVotingNotification(
    phoneNumber: string,
    electionTitle: string,
    endDate: string
  ): Promise<boolean> {
    const message = `JKUAT Voting: "${electionTitle}" is now open. Vote before ${endDate}. Login at ${process.env.FRONTEND_URL}`;
    
    return this.sendSMS({
      to: phoneNumber,
      message,
    });
  }

  /**
   * Send vote confirmation
   */
  public async sendVoteConfirmation(
    phoneNumber: string,
    verificationCode: string
  ): Promise<boolean> {
    const message = `JKUAT Voting: Your vote has been recorded. Verification code: ${verificationCode}. Keep this for your records.`;
    
    return this.sendSMS({
      to: phoneNumber,
      message,
    });
  }

  /**
   * Send election reminder
   */
  public async sendElectionReminder(
    phoneNumber: string,
    electionTitle: string,
    hoursRemaining: number
  ): Promise<boolean> {
    const message = `JKUAT Voting Reminder: ${hoursRemaining} hours left to vote in "${electionTitle}". Don't miss out!`;
    
    return this.sendSMS({
      to: phoneNumber,
      message,
    });
  }

  /**
   * Send password reset code
   */
  public async sendPasswordResetCode(
    phoneNumber: string,
    resetCode: string
  ): Promise<boolean> {
    const message = `JKUAT Voting: Your password reset code is ${resetCode}. Valid for 30 minutes. If you didn't request this, please ignore.`;
    
    return this.sendSMS({
      to: phoneNumber,
      message,
    });
  }

  /**
   * Send account security alert
   */
  public async sendSecurityAlert(
    phoneNumber: string,
    alertType: 'login' | 'password_change' | 'suspicious_activity',
    details?: string
  ): Promise<boolean> {
    let message = 'JKUAT Voting Security Alert: ';
    
    switch (alertType) {
      case 'login':
        message += `New login to your account. ${details || ''}`;
        break;
      case 'password_change':
        message += 'Your password has been changed. If this wasn\'t you, contact support immediately.';
        break;
      case 'suspicious_activity':
        message += `Suspicious activity detected. ${details || 'Please verify your account.'}`;
        break;
    }

    return this.sendSMS({
      to: phoneNumber,
      message,
    });
  }

  /**
   * Send bulk SMS
   */
  public async sendBulkSMS(
    recipients: string[],
    message: string,
    batchSize: number = 100
  ): Promise<{ success: number; failed: number }> {
    if (!this.isEnabled) {
      logger.warn('SMS service is disabled');
      return { success: 0, failed: recipients.length };
    }

    let successCount = 0;
    let failCount = 0;

    // Process in batches to avoid rate limits
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      const results = await Promise.allSettled(
        batch.map(recipient => 
          this.sendSMS({
            to: recipient,
            message,
          })
        )
      );

      successCount += results.filter(r => r.status === 'fulfilled' && r.value).length;
      failCount += results.filter(r => r.status === 'rejected' || !r.value).length;

      // Add delay between batches to respect rate limits
      if (i + batchSize < recipients.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    logger.info(`Bulk SMS completed: ${successCount} sent, ${failCount} failed`);
    return { success: successCount, failed: failCount };
  }

  /**
   * Format phone number to international format
   */
  private formatPhoneNumber(phoneNumber: string): string {
    // Remove all non-digit characters
    let cleaned = phoneNumber.replace(/\D/g, '');

    // If number starts with 0, assume it's a Kenyan number
    if (cleaned.startsWith('0')) {
      cleaned = '254' + cleaned.substring(1);
    }

    // If number doesn't start with country code, add Kenya's code
    if (!cleaned.startsWith('254') && cleaned.length === 9) {
      cleaned = '254' + cleaned;
    }

    // Add + prefix
    if (!cleaned.startsWith('+')) {
      cleaned = '+' + cleaned;
    }

    return cleaned;
  }

  /**
   * Validate phone number format
   */
  public isValidPhoneNumber(phoneNumber: string): boolean {
    const cleaned = phoneNumber.replace(/\D/g, '');
    
    // Check for Kenyan phone number format
    // Should be 12 digits with country code (254XXXXXXXXX)
    // Or 10 digits starting with 0 (0XXXXXXXXX)
    return (
      (cleaned.length === 12 && cleaned.startsWith('254')) ||
      (cleaned.length === 10 && cleaned.startsWith('07')) ||
      (cleaned.length === 10 && cleaned.startsWith('01')) ||
      (cleaned.length === 9)
    );
  }

  /**
   * Get SMS delivery status
   */
  public async getMessageStatus(messageSid: string): Promise<string | null> {
    if (!this.isEnabled) {
      return null;
    }

    try {
      const message = await this.client.messages(messageSid).fetch();
      return message.status;
    } catch (error) {
      logger.error('Failed to get message status:', error);
      return null;
    }
  }

  /**
   * Send test SMS
   */
  public async sendTestSMS(phoneNumber: string): Promise<boolean> {
    const message = 'This is a test message from JKUAT Voting System. Your SMS service is working correctly.';
    
    return this.sendSMS({
      to: phoneNumber,
      message,
    });
  }
}

// Export singleton instance
export const smsService = SMSService.getInstance();

export default smsService;