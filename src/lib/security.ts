/**
 * Security utilities for AI Content Replacer Pro
 * Implements enterprise-level security measures
 */

// Input sanitization utilities
export class InputSanitizer {
  /**
   * Sanitize text input to prevent XSS attacks
   */
  static sanitizeText(input: string): string {
    if (!input || typeof input !== 'string') return '';
    
    return input
      .replace(/[<>]/g, '') // Remove potentially dangerous characters
      .replace(/javascript:/gi, '') // Remove javascript: protocols
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  }

  /**
   * Sanitize API key format
   */
  static sanitizeApiKey(apiKey: string): string {
    if (!apiKey || typeof apiKey !== 'string') return '';
    
    // Remove any non-alphanumeric characters except dashes and underscores
    return apiKey.replace(/[^a-zA-Z0-9\-_]/g, '');
  }

  /**
   * Validate email format
   */
  static validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate URL format
   */
  static validateUrl(url: string): boolean {
    try {
      const urlObject = new URL(url);
      return ['http:', 'https:'].includes(urlObject.protocol);
    } catch {
      return false;
    }
  }

  /**
   * Sanitize business profile data
   */
  static sanitizeBusinessProfile(profile: any): any {
    return {
      businessName: this.sanitizeText(profile.businessName || ''),
      businessType: this.sanitizeText(profile.businessType || ''),
      description: this.sanitizeText(profile.description || ''),
      targetAudience: this.sanitizeText(profile.targetAudience || ''),
      services: this.sanitizeText(profile.services || ''),
      location: this.sanitizeText(profile.location || ''),
      phone: this.sanitizeText(profile.phone || ''),
      email: this.validateEmail(profile.email || '') ? profile.email : '',
      website: this.validateUrl(profile.website || '') ? profile.website : '',
      tone: this.sanitizeText(profile.tone || ''),
       keywords: Array.isArray(profile.keywords) 
        ? profile.keywords.map((k: string) => this.sanitizeText(k)).filter((k: string) => k.length > 0)
        : [],
      usp: this.sanitizeText(profile.usp || '')
    };
  }
}

// API key encryption utilities
export class ApiKeyManager {
  /**
   * Encrypt API key for secure storage
   * In production, this should use proper encryption libraries
   */
  static encryptApiKey(apiKey: string): string {
    if (!apiKey) return '';
    
    // Simple base64 encoding for demo - use proper encryption in production
    if (typeof window !== 'undefined') {
      return btoa(apiKey);
    }
    return apiKey; // Fallback for server-side
  }

  /**
   * Decrypt API key for usage
   */
  static decryptApiKey(encryptedKey: string): string {
    if (!encryptedKey) return '';
    
    try {
      if (typeof window !== 'undefined') {
        return atob(encryptedKey);
      }
      return encryptedKey; // Fallback for server-side
    } catch {
      return '';
    }
  }

  /**
   * Validate API key format for different providers
   */
  static validateApiKeyFormat(provider: string, apiKey: string): boolean {
    const patterns = {
      openai: /^sk-[a-zA-Z0-9]{48,}$/,
      anthropic: /^sk-ant-[a-zA-Z0-9_-]{95,}$/,
      google: /^[a-zA-Z0-9_-]{39}$/,
      groq: /^gsk_[a-zA-Z0-9]{56}$/
    };

    const pattern = patterns[provider as keyof typeof patterns];
    return pattern ? pattern.test(apiKey) : apiKey.length > 0;
  }

  /**
   * Mask API key for display purposes
   */
  static maskApiKey(apiKey: string): string {
    if (!apiKey || apiKey.length < 8) return '****';
    
    const start = apiKey.substring(0, 4);
    const end = apiKey.substring(apiKey.length - 4);
    const middle = '*'.repeat(Math.min(apiKey.length - 8, 20));
    
    return `${start}${middle}${end}`;
  }
}

// Rate limiting utilities
export class RateLimiter {
  private static requests: Map<string, number[]> = new Map();

  /**
   * Check if request is allowed based on rate limits
   */
  static isAllowed(identifier: string, maxRequests: number = 100, windowMs: number = 3600000): boolean {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get existing requests for this identifier
    let userRequests = this.requests.get(identifier) || [];
    
    // Filter out old requests
    userRequests = userRequests.filter(timestamp => timestamp > windowStart);
    
    // Check if under limit
    if (userRequests.length >= maxRequests) {
      return false;
    }
    
    // Add current request
    userRequests.push(now);
    this.requests.set(identifier, userRequests);
    
    return true;
  }

  /**
   * Get remaining requests for identifier
   */
  static getRemainingRequests(identifier: string, maxRequests: number = 100, windowMs: number = 3600000): number {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    const userRequests = (this.requests.get(identifier) || [])
      .filter(timestamp => timestamp > windowStart);
    
    return Math.max(0, maxRequests - userRequests.length);
  }

  /**
   * Reset rate limit for identifier
   */
  static resetLimit(identifier: string): void {
    this.requests.delete(identifier);
  }
}

// Content security utilities
export class ContentSecurityManager {
  /**
   * Scan content for potentially malicious patterns
   */
  static scanContent(content: string): { safe: boolean; issues: string[] } {
    const issues: string[] = [];
    
    // Check for script tags
    if (/<script[^>]*>.*?<\/script>/gi.test(content)) {
      issues.push('Script tags detected');
    }
    
    // Check for javascript: protocols
    if (/javascript:/gi.test(content)) {
      issues.push('JavaScript protocols detected');
    }
    
    // Check for event handlers
    if (/on\w+\s*=/gi.test(content)) {
      issues.push('Event handlers detected');
    }
    
    // Check for iframe with suspicious sources
    if (/<iframe[^>]+src=["'][^"']*(?:javascript:|data:)/gi.test(content)) {
      issues.push('Suspicious iframe detected');
    }
    
    // Check for excessive HTML complexity (potential DoS)
    const htmlTags = content.match(/<[^>]+>/g) || [];
    if (htmlTags.length > 1000) {
      issues.push('Excessive HTML complexity');
    }
    
    return {
      safe: issues.length === 0,
      issues
    };
  }

  /**
   * Clean content while preserving formatting
   */
  static cleanContent(content: string): string {
    return content
      // Remove script tags completely
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      // Remove javascript: protocols
      .replace(/javascript:/gi, '')
      // Remove event handlers but keep the element
      .replace(/\s+on\w+\s*=\s*["'][^"']*["']/gi, '')
      // Clean up extra whitespace
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Validate content length and complexity
   */
  static validateContentLimits(content: string): { valid: boolean; reason?: string } {
    // Check content length (max 100KB)
    if (content.length > 100000) {
      return { valid: false, reason: 'Content too large (max 100KB)' };
    }
    
    // Check for reasonable line length
    const lines = content.split('\n');
    const longLines = lines.filter(line => line.length > 10000);
    if (longLines.length > 0) {
      return { valid: false, reason: 'Lines too long (max 10KB per line)' };
    }
    
    // Check for reasonable number of lines
    if (lines.length > 10000) {
      return { valid: false, reason: 'Too many lines (max 10,000)' };
    }
    
    return { valid: true };
  }
}

// Session management utilities
export class SessionManager {
  private static readonly SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours
  
  /**
   * Create secure session token
   */
  static createSessionToken(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2);
    const tokenData = `${timestamp}-${random}`;
    
    if (typeof window !== 'undefined') {
      return btoa(tokenData);
    }
    return tokenData; // Fallback for server-side
  }

  /**
   * Validate session token
   */
  static validateSessionToken(token: string): boolean {
    try {
      let decoded: string;
      if (typeof window !== 'undefined') {
        decoded = atob(token);
      } else {
        decoded = token; // Fallback for server-side
      }
      
      const [timestamp] = decoded.split('-');
      const tokenAge = Date.now() - parseInt(timestamp);
      
      return tokenAge < this.SESSION_DURATION;
    } catch {
      return false;
    }
  }

  /**
   * Generate secure nonce for forms
   */
  static generateNonce(): string {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }
}

// Audit logging utilities
export class AuditLogger {
  private static logs: Array<{
    timestamp: number;
    action: string;
    user?: string;
    details?: any;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }> = [];

  /**
   * Log security event
   */
  static logSecurityEvent(action: string, severity: 'low' | 'medium' | 'high' | 'critical', details?: any, user?: string): void {
    this.logs.push({
      timestamp: Date.now(),
      action,
      user,
      details,
      severity
    });

    // In production, send to external logging service
    if (severity === 'critical') {
      console.error('CRITICAL SECURITY EVENT:', { action, details, user });
    }
  }

  /**
   * Get security logs
   */
  static getSecurityLogs(severity?: 'low' | 'medium' | 'high' | 'critical'): Array<any> {
    if (severity) {
      return this.logs.filter(log => log.severity === severity);
    }
    return [...this.logs];
  }

  /**
   * Clear old logs (keep last 1000)
   */
  static cleanupLogs(): void {
    if (this.logs.length > 1000) {
      this.logs.splice(0, this.logs.length - 1000);
    }
  }
}

// Export all security utilities
export default {
  InputSanitizer,
  ApiKeyManager,
  RateLimiter,
  ContentSecurityManager,
  SessionManager,
  AuditLogger
};