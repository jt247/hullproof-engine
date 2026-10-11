// Vocabulary the extractors match: names of calls, decorators and libraries that mean a protection, a request input, a
// data store or an outbound call. Matched against masked text (comments and string contents blanked). Data, kept apart
// from the logic so it can be read and extended in one place. Confidence rule: a known library API is high, a name from
// this list is medium, a name that only suggests the thing is low.
import type { Confidence } from '../types/index.ts';

// Packages whose import in a file makes a vocabulary hit in that file high confidence.
export const AUTH_PACKAGES = /next-auth|@auth\/|@clerk\/|@supabase\/|firebase-admin|firebase\/auth|passport|jsonwebtoken|\bjose\b|@kinde|lucia|better-auth|iron-session|@auth0|express-jwt|koa-jwt|@fastify\/jwt|@fastify\/auth|@nestjs\/passport|@nestjs\/jwt|flask_login|flask_jwt_extended|flask_httpauth|fastapi\.security|django\.contrib\.auth|rest_framework|authlib|python-jose|jwt\b/;
export const RATE_PACKAGES = /express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|@nestjs\/throttler|express-slow-down|flask_limiter|slowapi|django_ratelimit|ratelimit|limits\b|fastify-rate-limit|@fastify\/rate-limit|hono-rate-limiter/;

export interface Pattern { re: RegExp; via: string; confidence: Confidence }
const p = (re: RegExp, via: string, confidence: Confidence): Pattern => ({ re, via, confidence });

// Session read, JavaScript and TypeScript. A match means the handler asks who the caller is.
export const SESSION_JS: Pattern[] = [
  p(/\bAuthGuard\s*\(|@UseGuards\s*\([^)]*(?:Auth|Jwt|JWT|Session|Firebase|Clerk|Supabase)\w*Guard/, 'AuthGuard', 'high'),
  p(/\bgetServerSession\s*\(/, 'getServerSession', 'high'),
  p(/\b(?:supabase|client|sb)\w*\.auth\.(?:getUser|getSession|getClaims)\s*\(|\bauth\.(?:getUser|getSession)\s*\(/, 'auth.getUser', 'high'),
  p(/\bgetToken\s*\(\s*\{/, 'getToken', 'high'),
  p(/\b(?:jwt\.verify|jwtVerify|verifyIdToken|verifySessionCookie|jwt\.decode)\s*\(/, 'jwt verify', 'high'),
  p(/\bpassport\.authenticate\s*\(/, 'passport.authenticate', 'high'),
  p(/\b(?:getAuth|clerkClient|currentUser|auth)\s*\(\s*(?:req|request)?\s*\)/, 'auth()', 'medium'),
  p(/\b(?:req|request)\.(?:user|session|auth)\b|\bctx\.state\.user\b|\bres\.locals\.(?:user|session)\b|\bc\.get\(\s*['"](?:user|session|jwtPayload)/, 'request user', 'medium'),
  p(/\b(?:require|ensure|assert)(?:Auth|User|Login|Session|Authenticated|SignedIn)\w*\b/, 'require auth', 'medium'),
  p(/\b(?:is|check)(?:Authenticated|LoggedIn|Auth|Authorized|SignedIn)\w*\b/, 'is authenticated', 'medium'),
  p(/\b(?:get|find|load|fetch|resolve)?(?:Current|Session|Auth|Logged|Viewer|Signed)(?:In)?User\w*\s*\(|\bcurrentUser\w*\s*\(|\buserFrom(?:Token|Session|Cookie|Request)\w*\s*\(|\bgetUserFrom\w*\s*\(|\bgetViewer\w*\s*\(/, 'current user', 'medium'),
  p(/\bgetSession\s*\(/, 'getSession', 'medium'),
  p(/\bauthenticate\w*\s*\(|\bverifyToken\w*\s*\(|\bverifyJwt\w*\s*\(|\bwithAuth\w*\b|\bauthMiddleware\b|\bisAuthorized\s*\(|\bprotect\s*\(/, 'authenticate', 'medium'),
  p(/\b(?:req|request)\.cookies\.get\s*\(\s*['"][^'"]*(?:session|token|auth|jwt|sid)[^'"]*['"]|\bcookies\s*\(\s*\)\s*\.\s*get\s*\(\s*['"][^'"]*(?:session|token|auth|jwt|sid)[^'"]*['"]|\bcookies\.get\s*\(\s*['"][^'"]*(?:session|token|auth|jwt|sid)/i, 'session cookie read', 'low'),
  p(/\bheaders?\b[^;\n]{0,40}\bauthorization\b|\bauthorization\b\s*[\]:)]|['"]authorization['"]/i, 'authorization header', 'low'),
];

export const SESSION_PY: Pattern[] = [
  p(/@(?:\w+\.)?(?:login_required|jwt_required|auth_required|token_required|permission_required|user_passes_test|authenticated|requires_auth)\b/, 'login decorator', 'high'),
  p(/\bDepends\s*\(\s*(?:get_current_\w*|oauth2_scheme|get_user\w*|require_\w*|current_\w*|verify_\w*|auth\w*|get_token\w*|\w*(?:auth|token|jwt|bearer)\w*)\s*\)|\bSecurity\s*\(|\bHTTPBearer\b|\bOAuth2PasswordBearer\b/, 'Depends(auth)', 'high'),
  p(/\b(?:get_jwt_identity|get_jwt|verify_jwt_in_request|jwt\.decode|decode_token)\s*\(/, 'jwt', 'high'),
  p(/\bpermission_classes\s*=\s*[\[(][^\])]*(?:IsAuthenticated|IsAdminUser|DjangoModelPermissions|IsAuthenticatedOrReadOnly)|\bLoginRequiredMixin\b|\bauthentication_classes\s*=\s*[\[(][^\])]*\w/, 'permission_classes', 'high'),
  p(/\bcurrent_user\b|\bg\.user\b|\brequest\.user\b|\brequest\.session\b|\bsession\s*\[|\bsession\.get\s*\(|\bauth\.get_user\b|\brequest\.auth\b/, 'current user', 'medium'),
  p(/\b(?:get|require|ensure)_(?:current_)?(?:user|session)\w*\s*\(|\bauthenticate\s*\(|\bis_authenticated\b|\bverify_token\w*\s*\(/, 'get user', 'medium'),
  p(/request\.headers(?:\.get\s*\(\s*|\s*\[\s*)['"]Authorization/i, 'authorization header', 'low'),
];

export const ROLE_JS: Pattern[] = [
  p(/\brole\s*(?:===?|!==?)\s*["'`](?:admin|owner|superadmin|staff|moderator|manager)/i, 'role compare', 'high'),
  p(/["'`](?:admin|owner|superadmin|staff)["'`]\s*(?:===?|!==?)\s*[\w.?]*role|roles?\.(?:includes|some)\(\s*["'`](?:admin|owner|staff)/i, 'role compare', 'high'),
  p(/@(?:Roles|PreAuthorize|Secured|RolesAllowed|HasRole|RequirePermissions|Permissions)\s*\(/, 'role decorator', 'high'),
  p(/\b(?:requireRole|require_role|checkRole|withRole|hasRole|hasPermission|hasAnyRole|assertRole|requirePermission|requireAdmin|assertAdmin|ensureAdmin|adminOnly|adminMiddleware|checkAdmin|isSuperAdmin)\w*\b|\b(?:can|ability\.can|authorize)\s*\(|\b(?:isAdmin|is_admin|isStaff|isSuperUser)\b/, 'role check', 'medium'),
  p(/\bis(?:Accounting|Moderator|Manager|Owner|Superuser|SuperAdmin|Deluxe|Admin)\w*\s*\(/, 'role check', 'medium'),
];
export const ROLE_PY: Pattern[] = [
  p(/@(?:\w+\.)?(?:roles_required|role_required|admin_required|staff_member_required|superuser_required|permission_required|user_passes_test|require_role|requires_roles|roles_accepted)\b/, 'role decorator', 'high'),
  p(/\b(?:IsAdminUser|DjangoModelPermissions|PermissionRequiredMixin|UserPassesTestMixin|IsSuperuser|IsStaff)\b/, 'permission class', 'high'),
  p(/\.(?:is_staff|is_superuser|is_admin)\b|\bhas_perms?\s*\(|\bcurrent_user\.(?:role|is_admin)|\buser\.role\s*(?:==|!=|in)\b|\brole\s*(?:==|!=)\s*['"](?:admin|staff|owner)/i, 'role compare', 'medium'),
  p(/\b(?:require|check|assert|ensure)_(?:admin|role|permission|staff|superuser)\w*\s*\(|\bDepends\s*\(\s*(?:require_admin|admin_required|get_admin\w*|check_admin\w*|require_role\w*|get_current_admin\w*)\)/, 'role check', 'medium'),
];

export const SIGNATURE: Pattern[] = [
  p(/\b(?:constructEvent|construct_event|constructEventAsync|webhooks\.verify|wh\.verify|Webhook\.construct|verifyWebhook\w*|validateWebhook\w*|verifySignature\w*|verify_signature\w*|validateSignature\w*|validate_signature\w*|checkSignature\w*|verifyHmac\w*|verifyRequestSignature|isValidSignature\w*|svix|verify_webhook\w*)\b/, 'signature verify', 'high'),
  p(/\b(?:timingSafeEqual|compare_digest|hash_equals|secure_compare|hmac\.Equal)\s*\(|\bcreateHmac\s*\(|\bhmac\.new\s*\(/, 'hmac compare', 'high'),
  p(/\bverify\w*\s*\(\s*(?:raw|body|payload|req|request|signature|sig)\b/i, 'verify call', 'medium'),
];

export const RATE: Pattern[] = [
  p(/\b(?:rateLimit|rateLimiter|slowDown|checkRateLimit|withRateLimit|ratelimit|Ratelimit|RateLimiterMemory|RateLimiterRedis|RateLimiter|throttle)\w*\s*[(.]|\b\w*(?:rate_?limit|ratelimit|limiter)\w*\s*\(|\b\w*(?:[lL]imiter|RateLimit|rateLimit|ratelimit|[tT]hrottler?)\w*\b/i, 'rate limit', 'medium'),
  p(/@(?:Throttle|SkipThrottle|UseGuards\s*\(\s*ThrottlerGuard|\w*limiter\.limit|limiter\.limit|ratelimit|rate_limit|ratelimited|throttle)\b|\bthrottle_classes\s*=|\bThrottlerGuard\b|\bdefault_limits\b|\bDepends\s*\(\s*\w*(?:rate|limit)\w*\s*\)|\blimiter\.limit\s*\(/i, 'rate limit decorator', 'high'),
];

export const VALIDATION_JS: Pattern[] = [
  p(/\.(?:safeParse|safeParseAsync|parseAsync|spa)\s*\(/, 'schema parse', 'high'),
  p(/(?:\b(?!JSON|Date|Number|Math|url|URL|path|qs|querystring|yaml|toml|Intl|parseInt)[A-Za-z_$][\w$]*|\))\.parse\s*\(\s*(?:await\s+)?(?:req|request|body|params|query|input|data|formData|Object\.fromEntries|await)/, 'schema parse', 'high'),
  p(/\b(?:Joi|joi)\.\w+|\.validateAsync\s*\(|\byup\b|\bvalibot\b|\bajv\b|\bcelebrate\s*\(|\bcheckSchema\s*\(|\bvalidationResult\s*\(|\bvalidateRequest\s*\(|\bvalidateBody\s*\(|\bvalidateOrReject\s*\(|\bplainToInstance\s*\(|\bplainToClass\s*\(|\bTypeBox\b|\bType\.Object\s*\(/, 'validation library', 'high'),
  p(/\b(?:body|param|query|check|header|cookie)\s*\(\s*['"][\w.\[\]*]+['"]\s*\)\s*\.\s*(?:is\w+|not\w*|trim|escape|exists|notEmpty|optional|matches|isLength|custom)\b/, 'express-validator', 'high'),
  p(/\.input\s*\(\s*(?:z\.|\w+Schema)/, 'trpc input', 'high'),
  p(/\bschema\s*:\s*\{|\bschema\s*:\s*\w+Schema\b/, 'route schema', 'medium'),
  p(/\b(?:validate|sanitize|validateInput|validatePayload|assertValid|isValid\w*)\s*\(/, 'validate call', 'low'),
];
export const VALIDATION_PY: Pattern[] = [
  p(/\.(?:model_validate|model_validate_json|parse_obj|parse_raw|validate_python)\s*\(/, 'pydantic', 'high'),
  p(/\b\w*Schema\s*\(\s*[^)]*\)\s*\.\s*(?:load|validate|loads)\s*\(|\bschema\.(?:load|validate)\s*\(/, 'marshmallow', 'high'),
  p(/\.(?:is_valid|validate_on_submit|full_clean)\s*\(/, 'form or serializer valid', 'high'),
  p(/\b(?:validate|jsonschema\.validate|cerberus|voluptuous|wtforms|FlaskForm)\b/, 'validation library', 'medium'),
];

export const AUDIT: Pattern[] = [
  p(/\b\w*(?:[aA]udit|ACTIVITY_?LOG|[aA]ctivity_?[lL]og|[sS]ecurity_?[lL]og|[aA]dmin_?[lL]og|[lL]og_?[aA]dmin_?[aA]ction)\w*\b|\b(?:record_?event|log_?event|logActivity|logSecurityEvent|recordEvent)\b/, 'audit log', 'medium'),
  p(/INSERT\s+INTO\s+(?:\w+\.)?(?:audit|activity|security_events?|admin_log)/i, 'audit insert', 'high'),
];

// Privileged column names: setting one of these from request data is the mass assignment weakness (SEC-AUTHZ-004).
export const PRIVILEGED = /^(?:role|roles|plan|tier|is_?admin|admin|is_?staff|is_?superuser|is_?super_?admin|permissions?|balance|credits?|subscription\w*|entitlements?|email_?verified|verified|account_?type|user_?type|org_?id|tenant_?id|owner_?id|stripe_?customer_?id|price|amount)$/i;
export const OWNER = /owner|user_?id|userId|tenant|account_?id|accountId|org_?id|orgId|organi[sz]ation|workspace|created_?by|createdBy|author|auth\.uid|current_?user|request\.user|session\.user|\.user\.id|ctx\.user|\buid\b|\bscope\b|policy|member|\.user\b|user\s*=|owner\s*=/i;

export const ADMIN_PATH = /(^|[\/_.-])(admin|administrator|backoffice|back-office|staff|superuser|internal|manage|management|moderator)([\/_.-]|$)/i;
export const AUTH_ENDPOINT = /(^|[\/_.-])(login|log-in|signin|sign-in|signup|sign-up|register|registration|logout|log-out|signout|sign-out|reset|forgot|forgotten|password|token|oauth|otp|verify|callback|magic|session|2fa|mfa|authenticate)([\/_.\-:]|$)/i;
export const PUBLIC_PATH = /^\/(?:api\/|v\d+\/|rest\/)?(health|healthz|ping|status|metrics|ready|readiness|liveness|robots\.txt|favicon\.ico|sitemap\.xml|public|static|assets|docs|openapi|swagger|\.well-known)(\/|$|\.)/i;

// Guards for allowlist style checks inside one function.
export const URL_GUARD = /[aA]llow(?:ed)?_?(?:[lL]ist|[hH]osts?|[dD]omains?|[oO]rigins?|[uU]rls?)|\.Hostname\s*\(\)|allow(?:ed)?_?(?:list|hosts?|domains?|origins?|urls?)|ALLOWED_\w+|whitelist|isPrivate|private-?ip|isSafeUrl|isAllowedUrl|validateUrl|assertPublicUrl|safeFetch|ssrf|ip\.isPrivate|ipaddress|is_private|hostname\s*(?:===?|!==?|in)\b|\.hostname\.(?:endsWith|includes|startsWith)|\bnew URL\([^)]*\)\.(?:hostname|host|origin)\s*(?:===?|!==?)|\bhosts?\.(?:has|includes)\(|\bdomains?\.(?:has|includes)\(|netloc\s*(?:==|in|!=)/;
export const REDIRECT_GUARD = /HasPrefix\(\s*\w+\s*,\s*"\/"|start_with\?\s*\(?\s*['"]\/|\burl_from\s*\(|allow_other_host:\s*false|str_starts_with\s*\(\s*\$\w+\s*,\s*['"]\/|Str::startsWith\(\s*\$\w+\s*,\s*['"]\/|[aA]llowed(?:Redirect|Host|Url)s?\b|startsWith\(\s*['"]\/(?!\/)|allow(?:ed)?_?(?:list|redirects?|hosts?|urls?)|ALLOWED_\w+|whitelist|is_safe_url|url_has_allowed_host_and_scheme|isSafeRedirect|isAllowedRedirect|safe_redirect|safeRedirect|sanitizeRedirect|\.origin\s*(?:===?|!==?)|\.hostname\s*(?:===?|!==?)|netloc\s*(?:==|in|!=)|\bnew URL\([^)]*\)\.(?:host|hostname|origin)|startswith\(\s*['"]\//;
export const SIZE_GUARD = /\bmax:\d+|(?:\.size|\.length|byteLength|content_?length|\.len\b)\s*(?:>=?|<=?)|(?:>=?|<=?)\s*(?:MAX_\w+|\w*[mM]ax\w*)|limits\s*:\s*\{[^}]*fileSize|maxFileSize|max_?file_?size|MAX_CONTENT_LENGTH|FILE_UPLOAD_MAX_MEMORY_SIZE|DATA_UPLOAD_MAX|max_?size|fileSize|MaxFileSizeValidator|maxSize|ParseFilePipe|\bmax_length\b|\bcontent_length_range\b|\blimit\s*:\s*['"]?\d/i;
export const TYPE_GUARD = /\bmimes:|\bmimetypes:|\|image\b|\bextensions:|(?:mimetype|mime_?type|content_?type|\.type|extname|\.ext\b|splitext)\b[^;\n]{0,80}(?:===|!==|==|!=|\.includes|\.startsWith|\.endsWith|\.match|\bin\b|\.test\()|(?:includes|has|test|startsWith|endsWith)\([^)]*\b(?:mimetype|mime|\.type|ext|content_?type)|fileFilter|allowed(?:Types|Extensions|Mimes?|_extensions|_types)|ALLOWED_\w+|fileTypeFromBuffer|file-type|imghdr|\bmagic\b|secure_filename|FileTypeValidator|ParseFilePipe|\bfiletype\.|python-magic/i;
export const CLAMP = /Math\.(?:min|max)\s*\(|\bmin\s*\(|\]\s*\.min\b|\.clamp\b|\.min\s*\(|\bclamp\s*\(|\bMAX_\w+|\.max\s*\(\s*\d+|\bmaxLimit\b|\bMAX_PAGE\w*|\bPAGE_SIZE_MAX\w*|le\s*=\s*\d+|\bmax_value\b|Number\.isInteger|\bmax_page_size\b|\bpaginate_by\b|\bPAGE_SIZE\b|\bmaximum\b|\.int\(\)\.max|\.positive\(\)\.max|\.lte\s*\(/;
