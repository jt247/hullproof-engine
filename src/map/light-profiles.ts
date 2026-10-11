// Vocabulary for the second wave languages: Go, Ruby (Rails) and PHP (Laravel). Same idea as vocab.ts: names of calls,
// filters and libraries that mean a protection, a request input, a data store or an outbound call, matched against masked
// text. A known library API is high, a name from this list is medium, a name that only suggests the thing is low.
import type { Confidence, InputSource, OutboundKind, StoreKind } from '../types/index.ts';
import type { MoreLang } from './lex-more.ts';
import type { Pattern } from './vocab.ts';

const p = (re: RegExp, via: string, confidence: Confidence): Pattern => ({ re, via, confidence });

export interface DataRule {
  re: RegExp;                          // matches up to and including the "(" of the call, or the call name for bare words
  store: StoreKind;
  verb: number;                        // capture group that holds the verb
  target: number | null;               // capture group that holds the model or table name
  conf: Confidence;
}
export interface OutRule { kind: OutboundKind; re: RegExp; guard: 'url' | 'redirect' | null; conf: Confidence; arg?: number }

export interface Profile {
  lang: MoreLang;
  session: Pattern[]; role: Pattern[]; decoSession: Pattern[]; decoRole: Pattern[]; signature: Pattern[]; rate: Pattern[]; validation: Pattern[]; audit: Pattern[];
  sources: RegExp;                     // an expression that is request data
  trusted: RegExp;                     // an expression that comes from the session
  reads: [InputSource, RegExp][];
  identRe: RegExp;                     // one identifier, with its sigil
  data: DataRule[];
  sqlCall: RegExp;                     // a call that sends text to the database
  outbound: OutRule[];
  exits: RegExp;                       // a statement that stops the request
  guardVars: string[];                 // names the guard test looks for after an assignment, besides the assigned name
  verbs: { read: RegExp; write: RegExp; del: RegExp };
}

const AUDIT_ALL: Pattern[] = [
  p(/\b\w*(?:[aA]udit|ACTIVITY_?LOG|[aA]ctivity_?[lL]og|[sS]ecurity_?[lL]og|[aA]dmin_?[lL]og)\w*\b|\b(?:record_?event|log_?event|logActivity|LogActivity|RecordEvent)\b/, 'audit log', 'medium'),
  p(/INSERT\s+INTO\s+(?:\w+\.)?(?:audit|activity|security_events?|admin_log)/i, 'audit insert', 'high'),
];

// ---- Go (net/http, chi, gin, echo, fiber, gorilla/mux) ---------------------------------------------------------------
const GO: Profile = {
  lang: 'go',
  session: [
    p(/\b(?:jwt\.Parse(?:WithClaims)?|jwtauth\.(?:Verifier|Authenticator|FromContext|VerifyRequest)|jwtware\.New|VerifyIDToken|VerifySessionCookie)\b/, 'jwt verify', 'high'),
    p(/\b(?:sessions\.(?:Get|NewCookieStore)|session\.Default\s*\(|session\.Get\s*\(|sessionStore\.Get\s*\(|SessionManager\.\w+\s*\()/, 'session store', 'high'),
    p(/\bc\.(?:Get|MustGet)\s*\(\s*["'](?:user|userID|user_id|claims|currentUser|jwt|auth)\w*["']|\bc\.Locals\s*\(\s*["'](?:user|userID|claims|jwt)\w*["']|\bc\.Get\s*\(\s*(?:userKey|UserKey|ctxUser)\w*\s*\)|\.Context\(\)\.Value\s*\(\s*\w*(?:[uU]ser|[cC]laims|[aA]uth)\w*\s*\)|\bctx\.Value\s*\(\s*\w*(?:[uU]ser|[cC]laims|[aA]uth)\w*\s*\)/, 'request user', 'medium'),
    p(/\b(?:CurrentUser|GetUser|UserFromContext|UserFromRequest|GetClaims|ClaimsFromContext|GetUserID|UserIDFromContext|MustUser|AuthUser|GetCurrentUser|RequireUser|RequireAuth|Authenticate|AuthRequired|IsAuthenticated|CheckAuth|ValidateToken|VerifyToken|ParseToken|RequireLogin)\w*\s*\(/i, 'current user', 'medium'),
    p(/\b[a-z]\w*(?:Auth|Authn|Jwt|JWT|Login|Session)\w*Middleware\b|\bmiddleware\.(?:JWT|JWTWithConfig|BasicAuth|KeyAuth|BearerAuth|Auth)\w*\b|\bAuthMiddleware\b|\bauthMiddleware\b|\b(?:RequireAuth|RequireLogin|AuthRequired|Authenticated|JWTAuth|BasicAuth|KeyAuth|TokenAuth)\b/i, 'auth middleware', 'medium'),
    p(/\b(?:r|req)\.Header\.Get\s*\(\s*["']Authorization["']\s*\)|\bc\.GetHeader\s*\(\s*["']Authorization["']\s*\)/, 'authorization header', 'low'),
  ],
  role: [
    p(/\b(?:HasRole|HasPermission|RequireRole|RequireRoles|RequireAdmin|AdminOnly|IsAdmin|IsSuperAdmin|CheckRole|CheckPermission|RequirePermission)\w*\s*\(|\b(?:casbin\.\w+|enforcer\.Enforce\w*)\s*\(|\bAdminMiddleware\b|\badminOnly\b|\brequireAdmin\b|\bRoleMiddleware\b/i, 'role check', 'medium'),
    p(/\.(?:Role|IsAdmin|IsStaff)\s*(?:==|!=)|\brole\s*(?:==|!=)\s*"(?:admin|owner|staff|superadmin)"|"(?:admin|owner|superadmin)"\s*(?:==|!=)\s*\w+\.Role/, 'role compare', 'high'),
  ],
  signature: [
    p(/\b(?:webhook\.ConstructEvent\w*|ConstructEvent|VerifyWebhook\w*|VerifySignature\w*|ValidateSignature\w*|CheckSignature\w*|ValidateWebhook\w*|VerifyHMAC\w*|IsValidSignature\w*|verifySignature\w*|validateSignature\w*)\s*\(/, 'signature verify', 'high'),
    p(/\bhmac\.Equal\s*\(|\bsubtle\.ConstantTimeCompare\s*\(/, 'hmac compare', 'high'),
  ],
  rate: [
    p(/\b(?:httprate\.\w+|tollbooth\.\w+|limiter\.(?:New|Limit|Allow|Middleware)\w*|ratelimit\.\w+|rate\.NewLimiter|NewLimiter|RateLimit\w*|rateLimit\w*|Throttle\w*|ratelimiter\.\w+|\w*[lL]imiter\.(?:Allow|Wait|Take|Reserve)\w*)/, 'rate limit', 'medium'),
  ],
  validation: [
    p(/\b(?:validator\.New|validate\.(?:Struct|Var|StructCtx)|v\.(?:Struct|Var)\s*\(|\w*[vV]alidator\.(?:Struct|Var)|validation\.ValidateStruct|govalidator\.\w+)|\.Validate\s*\(/, 'validator', 'high'),
    p(/\.(?:ShouldBind|ShouldBindJSON|ShouldBindQuery|BindJSON|Bind|BodyParser|QueryParser)\s*\(/, 'bind with validation tags', 'low'),
    p(/`[^`]*(?:validate|binding):"/, 'struct tags', 'medium'),
  ],
  audit: AUDIT_ALL,
  decoSession: [], decoRole: [],
  sources: /\b(?:r|req|request)\.(?:URL|Form|PostForm|Body|Header|FormValue|PostFormValue|Cookie|PathValue|MultipartForm)\b|\bchi\.URLParam\s*\(|\bmux\.Vars\s*\(|\bc\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|QueryParam|FormValue|Cookie|GetHeader|BodyParser|Body|QueryArray|GetQuery|QueryParams|FormFile|MultipartForm)\b|\bc\.Request\b/,
  trusted: /\bclaims\b|\bc\.(?:Get|MustGet)\s*\(\s*["'](?:user|userID|user_id|claims)|\bc\.Locals\s*\(\s*["'](?:user|userID|claims)|\bUserFromContext|\bCurrentUser\b|\bGetUserID\b|\bcurrentUser\b|\bsession\.(?:UserID|User)\b/,
  reads: [
    ['body', /\bjson\.NewDecoder\s*\(\s*(?:r|req|c\.Request)\.Body|\bio(?:util)?\.ReadAll\s*\(\s*(?:r|req|c\.Request)\.Body|\b(?:r|req|c\.Request)\.Body\b|\.(?:ShouldBindJSON|BindJSON|ShouldBind|Bind|BodyParser|GetRawData)\s*\(|\bc\.Body\s*\(\s*\)/],
    ['query', /\b(?:r|req)\.URL\.Query\s*\(|\bc\.(?:Query|DefaultQuery|QueryParam|GetQuery|QueryArray|QueryParams|QueryParser)\b|\.URL\.RawQuery/],
    ['params', /\bchi\.URLParam\s*\(|\bmux\.Vars\s*\(|\bc\.(?:Param|Params|ParamsInt|ParamsParser)\b|\.PathValue\s*\(/],
    ['headers', /\b(?:r|req)\.Header\b|\bc\.(?:GetHeader|Request\.Header)\b/],
    ['cookies', /\b(?:r|req)\.Cookies?\s*\(|\bc\.Cookie\s*\(|\bc\.Cookies\s*\(/],
    ['form', /\b(?:r|req)\.(?:FormValue|PostFormValue|ParseForm|PostForm|Form)\b|\bc\.(?:PostForm|DefaultPostForm|FormValue)\b/],
    ['file', /\b(?:r|req)\.FormFile\s*\(|\.ParseMultipartForm\s*\(|\bc\.(?:FormFile|MultipartForm)\s*\(|\bmultipart\.\w+|\.MultipartReader\s*\(/],
  ],
  identRe: /(?<![.\w])([A-Za-z_]\w*)/g,
  data: [
    { re: /\b(?:\w*(?:db|DB|Db)|tx|gorm|\w*repo|\w*Repo|dao|\w*Dao)\s*\.\s*(?:\w+\s*\([^()]*\)\s*\.\s*)*(Where|First|Find|Take|Last|Create|Save|Delete|Updates|Update|UpdateColumns|UpdateColumn|Select|Scan|Count|Pluck|Raw|Exec|Table|Model)\s*\(/, store: 'orm', verb: 1, target: null, conf: 'medium' },
    { re: /(?<![\w])\w*\.\s*(Query|QueryRow|QueryContext|QueryRowContext|QueryRowx|Queryx|Exec|ExecContext|NamedExec|GetContext|SelectContext)\s*\(\s*(?:ctx\s*,\s*)?(?=[^,()]*(?:["`]|\w))/, store: 'sql', verb: 1, target: null, conf: 'medium' },
    { re: /\b\w*[cC]ollection\w*\s*\.\s*(Find|FindOne|InsertOne|InsertMany|UpdateOne|UpdateMany|DeleteOne|DeleteMany|ReplaceOne|FindOneAndUpdate|FindOneAndDelete|CountDocuments)\s*\(/, store: 'mongo', verb: 1, target: null, conf: 'medium' },
    { re: /\b(?:rdb|redis|redisClient)\s*\.\s*(Get|Set|Del|HGet|HSet|Incr|Expire|SetEX)\s*\(/, store: 'redis', verb: 1, target: null, conf: 'medium' },
    { re: /\b(?:q|queries|querier|repo|repository|svc|service)\s*\.\s*(Get|List|Find|Create|Insert|Update|Delete|Remove|Save|Count|Search)([A-Z]\w*)\s*\(/, store: 'orm', verb: 1, target: 2, conf: 'low' },
    { re: /\b(?:os|ioutil)\s*\.\s*(Open|ReadFile|OpenFile|WriteFile|Create|Remove|RemoveAll|ReadDir|Stat|Rename)\s*\(|\bhttp\s*\.\s*(ServeFile|ServeContent)\s*\(|\bc\.(File|SendFile|Attachment|FileAttachment)\s*\(/, store: 'filesystem', verb: 1, target: null, conf: 'high' },
  ],
  sqlCall: /\.(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Raw|NamedExec|GetContext|SelectContext|Queryx|QueryRowx)\s*\(/,
  outbound: [
    { kind: 'http', re: /\bhttp\.(?:Get|Post|PostForm|Head)\s*\(|\b\w*[cC]lient\s*\.\s*(?:Do|Get|Post|Head)\s*\(|\bresty\.\w+|\.R\(\)\s*\.\s*(?:Get|Post|Put|Delete)\s*\(/, guard: 'url', conf: 'high', arg: 0 },
    { kind: 'http', re: /\bhttp\.NewRequest\s*\(/, guard: 'url', conf: 'high', arg: 1 },
    { kind: 'http', re: /\bhttp\.NewRequestWithContext\s*\(/, guard: 'url', conf: 'high', arg: 2 },
    { kind: 'redirect', re: /\bhttp\.Redirect\s*\(/, guard: 'redirect', conf: 'high', arg: 2 },
    { kind: 'redirect', re: /\bc\.Redirect\s*\(/, guard: 'redirect', conf: 'high', arg: 1 },
    { kind: 'redirect', re: /\bw\.Header\(\)\.Set\s*\(\s*["']Location["']/, guard: 'redirect', conf: 'high', arg: 1 },
    { kind: 'process', re: /\bexec\.Command(?:Context)?\s*\(|\bsyscall\.Exec\s*\(/, guard: null, conf: 'high' },
    { kind: 'email', re: /\bsmtp\.SendMail\s*\(|\bgomail\.\w+|\bsendgrid\.\w+|\bmailgun\.\w+/, guard: null, conf: 'medium' },
    { kind: 'ai_model', re: /\b(?:openai|anthropic|genai|ollama|cohere)\w*\.\w+(?:\.\w+)*\.(?:Create|New|Generate|Chat|Complete)\w*\s*\(/, guard: null, conf: 'medium' },
    { kind: 'payment', re: /\bstripe\.\w+|\bpaystack\w*\.\w+|\bpaddle\w*\.\w+/, guard: null, conf: 'medium' },
  ],
  exits: /\breturn\b|\bpanic\s*\(|\bc\.Abort\w*\s*\(|\bhttp\.Error\s*\(|\bw\.WriteHeader\s*\(\s*(?:http\.Status(?:Unauthorized|Forbidden)|40[13])|\bc\.JSON\s*\(\s*(?:http\.Status(?:Unauthorized|Forbidden)|40[13])/,
  guardVars: ['ok', 'err'],
  verbs: { read: /^(?:Find|First|Take|Last|Get|List|Select|Scan|Count|Pluck|Query|QueryRow\w*|Queryx|Search|Open|ReadFile|ReadDir|Stat|ServeFile|File|SendFile|Attachment|FileAttachment|HGet|FindOne|CountDocuments|Where|Model|Table|Raw|GetContext|SelectContext)$/, write: /^(?:Create|Save|Updates?|UpdateColumns?|Insert\w*|Exec\w*|NamedExec|Set\w*|HSet|Incr|Expire|WriteFile|OpenFile|Rename|ReplaceOne|FindOneAndUpdate|UpdateOne|UpdateMany)$/, del: /^(?:Delete\w*|Remove\w*|RemoveAll|Del|FindOneAndDelete)$/ },
};

// ---- Ruby (Rails) -----------------------------------------------------------------------------------------------------
const RB: Profile = {
  lang: 'rb',
  session: [
    p(/\b(?:authenticate_user!|authenticate_\w+!|doorkeeper_authorize!|authenticate_with_http_(?:basic|token)|authenticate_or_request_with_http_(?:basic|token)|require_login|require_user|require_authentication|authenticate_request|authorize_request|authenticate_token|logged_in_user|ensure_authenticated|ensure_logged_in|check_authentication|jwt_authenticate)(?![\w])/, 'authenticate filter', 'high'),
    p(/\b(?:current_user|current_account|current_member|current_admin|Current\.user|Current\.session|warden\.authenticate!?|user_signed_in\?|signed_in\?|logged_in\?|current_resource_owner|doorkeeper_token)\b|\bsession\[\s*:(?:user_id|user|account_id|uid|member_id|admin_id)\s*\]|\bsession\.(?:fetch|dig)\s*\(\s*:(?:user_id|user)/, 'current user', 'medium'),
    p(/\b(?:JWT\.decode|JsonWebToken\.decode|decode_token|decoded_token|verify_jwt|http_auth_header|bearer_token|auth_token|find_by_auth_token|authenticated_user)(?![\w])/, 'token', 'medium'),
    p(/request\.headers\[\s*['"]Authorization['"]\s*\]/, 'authorization header', 'low'),
  ],
  role: [
    p(/\b(?:authorize!?|authorize_resource|load_and_authorize_resource|authorize_admin|require_admin!?|admin_required|ensure_admin!?|check_admin|require_role|require_permission|verify_admin|admin_only|policy_scope|verify_authorized|verify_policy_scoped|can\?|cannot\?|authorize_user|require_staff|authenticate_admin!?|require_superuser)(?![\w])/, 'role check', 'medium'),
    p(/\b(?:current_user|user)\.(?:admin\?|role\s*(?:==|!=)|has_role\?|is_admin\?|staff\?|superuser\?|roles\.include\?)|\brole\s*(?:==|!=)\s*['"](?:admin|owner|staff)['"]|\.admin\?|\bhas_role\?\s*\(/, 'role compare', 'high'),
  ],
  signature: [
    p(/\b(?:Stripe::Webhook\.construct_event|construct_event|Webhook\.construct_event|verify_signature|valid_signature\?|verify_webhook|valid_webhook\?|Svix::Webhook|verify_hmac|signature_valid\?|webhook_valid\?|verify_github_signature|verify_request_signature)(?![\w])/, 'signature verify', 'high'),
    p(/\b(?:ActiveSupport::SecurityUtils\.secure_compare|Rack::Utils\.secure_compare|secure_compare|fixed_length_secure_compare)(?![\w])/, 'hmac compare', 'high'),
  ],
  rate: [
    p(/\b(?:Rack::Attack|rate_limit\s+to:|throttle\s*\(|rate_limited|RateLimiter|rack_attack|check_rate_limit)/, 'rate limit', 'medium'),
  ],
  validation: [
    p(/\.permit\s*\(|\bparams\.permit\b|\b\w+_params\b/, 'strong parameters', 'medium'),
    p(/\b(?:Dry::Validation|Dry::Schema|ActiveModel::Validations|validates_with|Contract\.new|Reform)\b|\.valid\?|\.validate!?\b|\.save!|\.create!|\.update!/, 'model validation', 'medium'),
  ],
  audit: AUDIT_ALL,
  decoSession: [], decoRole: [],
  sources: /\bparams\b|\brequest\.(?:body|raw_post|headers|cookies|params|query_parameters|request_parameters|GET|POST|query_string|original_url|referer|url|fullpath)\b|\bcookies\b\s*[[.]|\bheaders\[/,
  trusted: /\bcurrent_user\b|\bcurrent_account\b|\bcurrent_member\b|\bcurrent_admin\b|\bCurrent\.user\b|\bsession\[\s*:(?:user_id|user|account_id|uid)\s*\]|\bwarden\.user\b|\bcurrent_resource_owner\b/,
  reads: [
    ['body', /\brequest\.(?:body|raw_post)\b|\bparams\.(?:require|permit)\b|\bparams\[\s*:(?!id\b)\w+\s*\]|\b\w+_params\b|\bJSON\.parse\s*\(\s*request\.body/],
    ['query', /\brequest\.(?:query_parameters|GET|query_string)\b|\bparams\[\s*:(?:q|query|search|page|per_page|limit|sort|order|filter|offset|term)\w*\s*\]/],
    ['params', /\bparams\[\s*:(?:id|\w+_id|slug|token|uuid)\s*\]|\bparams\.fetch\s*\(\s*:id/],
    ['headers', /\brequest\.headers\b|\bheaders\[\s*['"]/],
    ['cookies', /\bcookies(?:\.signed|\.encrypted)?\s*\[/],
    ['form', /\brequest\.(?:POST|request_parameters)\b|\bparams\.require\b/],
    ['file', /\bparams\[\s*:(?:file|files|upload|image|avatar|attachment|document|photo|picture|csv)\w*\s*\]|\.attach\s*\(|\bActionDispatch::Http::UploadedFile\b|\.original_filename\b|\.tempfile\b/],
  ],
  identRe: /(?<![.\w@$:])(@{0,2}[A-Za-z_]\w*[?!]?)/g,
  data: [
    { re: /\b(?!(?:Rails|File|Dir|Time|Date|JSON|Rack|ENV|Net|URI|Base64|SecureRandom|Digest|OpenSSL|CGI|ERB|Redis|Sidekiq|ActionMailer|Kernel|Process|IO|Struct|Hash|Array|String|Integer|Float|Math|Logger|I18n|Faraday|HTTParty|Stripe|Pundit|Current|BCrypt|Devise|Warden|Open3|FileUtils|Tempfile|Pathname|YAML|CSV|Zlib|Timeout|Mutex|Thread|Gem|Bundler|ActiveRecord|ActiveSupport|ActionController|ApplicationController)\b)([A-Z]\w*(?:::[A-Z]\w+)*)\s*\.\s*(find|find_by|find_by!|find_by_\w+|where|find_or_create_by|find_or_initialize_by|create|create!|update|update!|update_all|destroy|destroy_all|destroy_by|delete|delete_all|delete_by|all|first|last|order|joins|includes|eager_load|preload|select|pluck|count|exists\?|new|insert_all|upsert|upsert_all|find_each|take|limit|sum|find_by_sql|left_joins|group|distinct|ids|none|unscoped|lock|offset|page|search|ransack)\b/, store: 'orm', verb: 2, target: 1, conf: 'medium' },
    { re: /\b(?:current_user|current_account|current_member|current_admin|@current_user|Current\.user)\s*\.\s*([a-z_]\w*)\s*\.\s*(find|find_by|find_by!|where|create|create!|build|new|destroy|update|first|last|all|order|exists\?|find_or_create_by|delete|count|take|pluck|select)\b/, store: 'orm', verb: 2, target: 1, conf: 'medium' },
    { re: /\b(?:ActiveRecord::Base\.connection|connection|conn|ApplicationRecord\.connection)\s*\.\s*(execute|exec_query|select_all|select_rows|select_value|select_one|exec_update|exec_delete|exec_insert)\b/, store: 'sql', verb: 1, target: null, conf: 'medium' },
    { re: /\b(?:Redis\.current|\$redis|REDIS|Rails\.cache)\s*\.\s*(get|set|del|hget|hset|hgetall|incr|expire|fetch|write|read|delete)\b/, store: 'redis', verb: 1, target: null, conf: 'medium' },
    { re: /\b(?:File|IO|FileUtils)\s*\.\s*(open|read|write|readlines|delete|unlink|rm|rm_rf|foreach|binread|binwrite|rename|mv|cp|copy_stream)\b|\b(send_file|send_data)\b/, store: 'filesystem', verb: 1, target: null, conf: 'high' },
  ],
  sqlCall: /\b(?:execute|exec_query|select_all|select_rows|select_value|find_by_sql|exec_update|exec_delete|exec_insert)\s*[\s(]/,
  outbound: [
    { kind: 'http', re: /\b(?:Net::HTTP(?:\.\w+)?|HTTParty\.\w+|Faraday(?:\.\w+)?|RestClient\.\w+|Typhoeus\.\w+|URI\.open|Excon\.\w+|Curl::\w+|Mechanize\.new)\b\s*\(?|\bopen\s*\(\s*(?:params|url|uri)|\bURI\.parse\s*\(/, guard: 'url', conf: 'high' },
    { kind: 'redirect', re: /\bredirect_to\b|\bredirect_back\b|\bresponse\.headers\[\s*['"]Location['"]\s*\]/, guard: 'redirect', conf: 'high' },
    { kind: 'process', re: /\b(?:system|exec|spawn|popen|Open3\.\w+|Kernel\.(?:system|exec|spawn|open)|IO\.popen|Process\.spawn|eval|instance_eval|class_eval|constantize|safe_constantize)\s*[\s(]|%x\b/, guard: null, conf: 'high' },
    { kind: 'email', re: /\b\w*Mailer\.\w+|\.deliver_(?:now|later)\b|\bSendGrid\b|\bMailgun\b/, guard: null, conf: 'medium' },
    { kind: 'ai_model', re: /\b(?:OpenAI::Client|Anthropic::Client|Anthropic\w*|OpenAI\w*|Gemini\w*)\.new\b/, guard: null, conf: 'medium' },
    { kind: 'payment', re: /\bStripe::\w+|\bPaystack\w*|\bPaddle\w*|\bPayPal\w*/, guard: null, conf: 'medium' },
  ],
  exits: /\breturn\b|\bhead\s+:|\brender\b[^\n]*\bstatus:\s*(?::?(?:unauthorized|forbidden|bad_request|not_found|unprocessable_entity)|40\d)|\bredirect_to\b|\braise\b|\bhead\s+40\d/,
  guardVars: [],
  verbs: { read: /^(?:find|find_by|find_by!|find_by_\w+|where|all|first|last|order|joins|includes|eager_load|preload|select|pluck|count|exists\?|find_each|take|limit|sum|find_by_sql|left_joins|group|distinct|ids|none|unscoped|lock|offset|page|search|ransack|build|new|get|read|fetch|select_all|select_rows|select_value|select_one|hget|hgetall|foreach|readlines|binread|send_file|send_data|open)$/, write: /^(?:create|create!|update|update!|update_all|find_or_create_by|find_or_initialize_by|insert_all|upsert|upsert_all|execute|exec_query|exec_update|exec_insert|set|write|hset|incr|expire|binwrite|rename|mv|cp|copy_stream)$/, del: /^(?:destroy|destroy_all|destroy_by|delete|delete_all|delete_by|exec_delete|del|unlink|rm|rm_rf)$/ },
};

// ---- PHP (Laravel) -------------------------------------------------------------------------------------------------------
const PHP: Profile = {
  lang: 'php',
  session: [
    p(/\bAuth::(?:user|id|check|guard|userOrFail)\b|\bauth\(\s*[^)]*\)\s*->\s*(?:user|id|check)\b|\$request->user\b|\brequest\(\)->user\b|\bJWTAuth::\w+|\$this->guard\(\)/, 'current user', 'high'),
    p(/\bAuthenticate::class|\bauth:sanctum\b|\bAuthenticateWithBasicAuth\b/, 'auth middleware', 'high'),
    p(/\bsession\(\s*['"](?:user_id|user|account_id|uid)['"]\s*\)|\$_SESSION\s*\[\s*['"](?:user_id|user|uid|account_id)['"]\s*\]|\$request->session\(\)->get\(\s*['"](?:user|user_id)|\bJWT::decode\s*\(|\bverifyIdToken\s*\(|\bbearerToken\s*\(|\bcheckToken\s*\(|\bvalidateToken\s*\(|\brequireLogin\s*\(|\bisLoggedIn\s*\(|\bgetAuthenticatedUser\s*\(|\bcurrentUser\s*\(/, 'session or token', 'medium'),
    p(/->header\(\s*['"]Authorization['"]\s*\)|\$_SERVER\[\s*['"]HTTP_AUTHORIZATION['"]\s*\]/, 'authorization header', 'low'),
  ],
  role: [
    p(/\$this->authorize(?:Resource|ForUser)?\s*\(|\bGate::(?:authorize|allows|denies|check|forUser|any|inspect)\s*\(|->can\s*\(|->cannot\s*\(|->authorizeResource\s*\(|->hasRole\s*\(|->hasAnyRole\s*\(|->hasPermissionTo\s*\(|->isAdmin\s*\(|\bRoleMiddleware::class|\bPermissionMiddleware::class|\bEnsureUserIsAdmin\b|\bIsAdmin::class|->isSuperAdmin\b|\bauthorizeForUser\s*\(/, 'role or policy', 'high'),
    p(/->role\s*(?:===?|!==?)\s*['"](?:admin|owner|staff|superadmin)['"]|->is_admin\b|->isAdmin\b/, 'role compare', 'medium'),
  ],
  signature: [
    p(/\b(?:Webhook::constructEvent|constructEvent|Webhook::verify\w*|verifyWebhook\w*|verifySignature\w*|isValidSignature\w*|validateSignature\w*|WebhookSignature\w*|SignatureValidator|verify_signature|Svix\\Webhook|checkSignature\w*|VerifyWebhookSignature)\b/, 'signature verify', 'high'),
    p(/\bhash_equals\s*\(/, 'hmac compare', 'high'),
  ],
  rate: [
    p(/['"]throttle(?::[^'"]+)?['"]|\bRateLimiter::\w+|->throttle\b|\bThrottleRequests\b|\bRateLimiter\b|\bthrottleWithRedis\b/, 'rate limit', 'high'),
  ],
  validation: [
    p(/\$request->validate\s*\(|->validate\s*\(\s*\[|\bValidator::make\s*\(|->validated\s*\(|->safe\s*\(\s*\)|\bvalidateWith\w*\s*\(|\$this->validate\s*\(|\bvalidator\s*\(/, 'laravel validation', 'high'),
    p(/\b[A-Z]\w*Request\s+\$\w+\b/, 'form request type', 'high'),
    p(/\bfilter_var\s*\(|\bfilter_input\s*\(|\bctype_digit\s*\(|\bis_numeric\s*\(/, 'validation function', 'medium'),
  ],
  audit: AUDIT_ALL,
  decoSession: [
    p(/\bmiddleware\s*\(\s*\[?[^)]*['"](?:auth|auth:\w+|auth\.basic|auth\.session|sanctum|jwt\.auth|jwt\.verify|passport|auth\.token)\b|['"](?:auth|auth:[\w,]+|auth\.basic|sanctum|verified|jwt\.auth|jwt\.verify|passport|auth\.token)['"]/, 'auth middleware', 'high'),
  ],
  decoRole: [
    p(/['"]can:[^'"]+['"]|['"](?:role|permission|role_or_permission|role:[^'"]+|permission:[^'"]+)['"]/, 'role middleware', 'high'),
  ],
  sources: /\$request\b|\brequest\s*\(\s*\)|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\bInput::\w+|\bRequest::\w+/,
  trusted: /\bAuth::(?:user|id)\b|\bauth\(\s*\)\s*->\s*(?:user|id)|\$request->user\b|\brequest\(\)->user\b|\$_SESSION\b|\$request->session\(\)/,
  reads: [
    ['body', /\$request->(?:input|all|json|post|only|except|validated|collect|getContent|safe|string|integer|boolean|get)\b|\brequest\s*\(\s*\)->(?:all|input|json)|\$_POST\b|\$_REQUEST\b|php:\/\/input|\$request\[/],
    ['query', /\$request->query\b|\$_GET\b|\$request->input\(\s*['"](?:q|query|search|page|per_page|limit|sort|order|filter|offset|term)/],
    ['params', /\$request->route\b|\$_GET\s*\[\s*['"]id['"]/],
    ['headers', /\$request->header\s*\(|\$request->headers\b|\$_SERVER\s*\[\s*['"]HTTP_|getallheaders\(/],
    ['cookies', /\$request->cookie\s*\(|\$_COOKIE\b|\bCookie::get\b/],
    ['form', /\$request->(?:post|only|all)\s*\(|\$_POST\b/],
    ['file', /\$request->(?:file|hasFile|allFiles)\s*\(|\$_FILES\b|\bUploadedFile\b|->getClientOriginalName\s*\(|move_uploaded_file\s*\(/],
  ],
  identRe: /(\$[A-Za-z_]\w*)/g,
  data: [
    { re: /\b(?!(?:DB|Auth|Gate|Cache|Storage|Log|Route|Http|Validator|Hash|Redirect|Mail|Session|Config|View|Event|Notification|Artisan|Schema|Queue|Bus|Cookie|Crypt|File|Lang|Password|RateLimiter|Redis|Response|URL|App|Blade|Carbon|Str|Arr|Collection|Facade|Inertia|Livewire|Request|Policy|Sanctum|Passport|JWTAuth|Stripe|Cashier|Socialite|Date|Number|Process|Pipeline|Context|Vite|Broadcast|Exception)\b)([A-Z]\w*)\s*::\s*(find|findOrFail|findOrNew|findMany|where|whereKey|whereIn|whereHas|whereNull|whereNotNull|whereBetween|whereDate|whereRaw|create|firstOrCreate|firstOrNew|updateOrCreate|updateOrInsert|insert|insertGetId|destroy|all|first|firstOrFail|firstWhere|paginate|simplePaginate|query|with|withCount|latest|oldest|orderBy|orderByDesc|select|selectRaw|pluck|count|exists|forceCreate|upsert|truncate|withTrashed|onlyTrashed|has|doesntHave|take|limit|skip|offset|cursor|chunk|lazy|search|filter|raw|inRandomOrder|get|sole|findSole|update|delete)\b/, store: 'orm', verb: 2, target: 1, conf: 'medium' },
    { re: /\bDB::(table|select|insert|update|delete|statement|raw|unprepared|selectOne|scalar|affectingStatement|transaction|connection)\s*\(\s*(?:['"]([\w.]+)['"])?/, store: 'sql', verb: 1, target: 2, conf: 'medium' },
    { re: /(?:\$request->user\(\)|\$request->user|auth\(\)->user\(\)|Auth::user\(\)|\$this->user|request\(\)->user\(\))\s*->\s*([a-z_]\w*)\s*\(\s*\)\s*->\s*(find|findOrFail|where|create|firstOrCreate|first|firstOrFail|get|paginate|delete|update|updateOrCreate|latest|orderBy|with|count|exists|pluck|take|save|attach|sync|detach|toggle|whereKey)\b/, store: 'orm', verb: 2, target: 1, conf: 'medium' },
    { re: /\bStorage::(?:disk\([^)]*\)->)?(put|putFile|putFileAs|get|delete|download|exists|copy|move|deleteDirectory|files|allFiles|path|response|readStream|temporaryUrl)\s*\(|\b(file_put_contents|file_get_contents|unlink|fopen|readfile|move_uploaded_file|rename|mkdir|rmdir|scandir|glob|fread|fwrite)\s*\(|\bresponse\(\)->(file|download)\s*\(|\$\w+->(move|store|storeAs|storePublicly|storePubliclyAs)\s*\(/, store: 'filesystem', verb: 1, target: null, conf: 'high' },
    { re: /\bCache::(get|put|forget|remember|pull|increment|add|rememberForever|flush|has)\s*\(|\bRedis::(get|set|del|hget|hset|incr|expire|setex)\s*\(/, store: 'redis', verb: 1, target: null, conf: 'medium' },
  ],
  sqlCall: /\bDB::(?:select|insert|update|delete|statement|raw|unprepared|selectOne|scalar|affectingStatement)\s*\(|->(?:whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw)\s*\(|\bmysqli_query\s*\(|\bpg_query\s*\(/,
  outbound: [
    { kind: 'http', re: /\bHttp::(?:get|post|put|patch|delete|withHeaders|withToken|withBasicAuth|timeout|acceptJson|asForm|asJson|send|retry|baseUrl|withOptions|head|accept|withBody|attach)\b|\bfile_get_contents\s*\(\s*\$|\bcurl_init\s*\(\s*\$|\bcurl_setopt\s*\([^,]*,\s*CURLOPT_URL\s*,\s*\$|\$(?:client|http|guzzle)\s*->\s*(?:get|post|put|patch|delete|request|send)\s*\(|\bfopen\s*\(\s*\$/, guard: 'url', conf: 'high' },
    { kind: 'redirect', re: /\bredirect\s*\(|\bRedirect::(?:to|away|intended|route|back)\s*\(|\bheader\s*\(\s*['"]Location:/, guard: 'redirect', conf: 'high' },
    { kind: 'process', re: /\b(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec|eval|assert|create_function|call_user_func(?:_array)?|Process::run|Artisan::call|unserialize|extract)\s*\(/, guard: null, conf: 'high' },
    { kind: 'email', re: /\bMail::(?:to|send|raw|queue|later|cc|bcc)\b|\bNotification::send\b|->notify\s*\(|\bmail\s*\(|\bPHPMailer\b/, guard: null, conf: 'medium' },
    { kind: 'ai_model', re: /\bOpenAI::\w+|\bAnthropic::\w+|\bOpenAI\\Client\b|\bPrism::\w+|\bGemini::\w+/, guard: null, conf: 'medium' },
    { kind: 'payment', re: /\\Stripe\\\w+|\bCashier::\w+|->charge\s*\(|->newSubscription\s*\(|\bPaystack::\w+|\bPaddle\w*|->checkout\s*\(|\bPayPal\w*/, guard: null, conf: 'medium' },
  ],
  exits: /\breturn\b|\babort(?:_if|_unless)?\s*\(|\bthrow\b|\bdie\s*\(|\bexit\s*\(|->deny\s*\(|\bredirect\s*\(|\bhttp_response_code\s*\(\s*40/,
  guardVars: [],
  verbs: { read: /^(?:find|findOrFail|findOrNew|findMany|where\w*|has|doesntHave|all|first|firstOrFail|firstWhere|paginate|simplePaginate|query|with|withCount|latest|oldest|orderBy\w*|select\w*|pluck|count|exists|withTrashed|onlyTrashed|take|limit|skip|offset|cursor|chunk|lazy|search|filter|raw|inRandomOrder|get|sole|findSole|table|selectOne|scalar|statement|file_get_contents|fopen|readfile|scandir|glob|fread|download|path|response|readStream|temporaryUrl|files|allFiles|remember|rememberForever|hget|pull|has)$/, write: /^(?:create|firstOrCreate|firstOrNew|updateOrCreate|updateOrInsert|insert|insertGetId|forceCreate|upsert|update|save|fill|forceFill|affectingStatement|unprepared|attach|sync|detach|toggle|push|putFile|putFileAs|put|file_put_contents|move_uploaded_file|rename|copy|mkdir|fwrite|increment|decrement|touch|add|set|hset|incr|expire|setex|move|store)$/, del: /^(?:destroy|delete|forceDelete|truncate|unlink|rmdir|deleteDirectory|forget|flush|del|restore)$/ },
};

export const PROFILES: Record<MoreLang, Profile> = { go: GO, rb: RB, php: PHP };
