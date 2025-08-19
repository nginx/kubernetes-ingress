# APPolicy

**Group:** `appprotect.f5.com`  
**Version:** `v1beta1`  
**Kind:** `APPolicy`  
**Scope:** `Namespaced`

## Description

The `APPolicy` resource defines a security policy for NGINX App Protect. It allows you to configure a wide range of security features, including bot defense, blocking settings, and application language support.

## Spec Fields

The `.spec` object supports the following fields:

| Field | Type | Description |
|---|---|---|
| `modifications` | `array` | List of configuration values. |
| `modifications[].action` | `string` | String configuration value. |
| `modifications[].description` | `string` | String configuration value. |
| `modifications[].entity` | `object` | Configuration object. |
| `modifications[].entity.name` | `string` | String configuration value. |
| `modifications[].entityChanges` | `object` | Configuration object. |
| `modifications[].entityChanges.type` | `string` | String configuration value. |
| `modificationsReference` | `object` | Configuration object. |
| `modificationsReference.link` | `string` | String configuration value. |
| `policy` | `object` | Defines the App Protect policy |
| `policy.applicationLanguage` | `string` | Allowed values: `"iso-8859-10"`, `"iso-8859-6"`, `"windows-1255"`, `"auto-detect"`, `"koi8-r"`, `"gb18030"`, `"iso-8859-8"`, `"windows-1250"`, `"iso-8859-9"`, `"windows-1252"`, `"iso-8859-16"`, `"gb2312"`, `"iso-8859-2"`, `"iso-8859-5"`, `"windows-1257"`, `"windows-1256"`, `"iso-8859-13"`, `"windows-874"`, `"windows-1253"`, `"iso-8859-3"`, `"euc-jp"`, `"utf-8"`, `"gbk"`, `"windows-1251"`, `"big5"`, `"iso-8859-1"`, `"shift_jis"`, `"euc-kr"`, `"iso-8859-4"`, `"iso-8859-7"`, `"iso-8859-15"`. |
| `policy.blocking-settings` | `object` | Configuration object. |
| `policy.blocking-settings.evasions` | `array` | List of configuration values. |
| `policy.blocking-settings.evasions[].description` | `string` | Allowed values: `"%u decoding"`, `"Apache whitespace"`, `"Bad unescape"`, `"Bare byte decoding"`, `"Directory traversals"`, `"IIS backslashes"`, `"IIS Unicode codepoints"`, `"Multiple decoding"`, `"Multiple slashes"`, `"Semicolon path parameters"`, `"Trailing dot"`, `"Trailing slash"`. |
| `policy.blocking-settings.evasions[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.blocking-settings.evasions[].maxDecodingPasses` | `integer` | Numeric configuration value. |
| `policy.blocking-settings.http-protocols` | `array` | List of configuration values. |
| `policy.blocking-settings.http-protocols[].description` | `string` | Allowed values: `"Unescaped space in URL"`, `"Unparsable request content"`, `"Several Content-Length headers"`, `"POST request with Content-Length: 0"`, `"Null in request"`, `"No Host header in HTTP/1.1 request"`, `"Multiple host headers"`, `"Host header contains IP address"`, `"High ASCII characters in headers"`, `"Header name with no header value"`, `"CRLF characters before request start"`, `"Content length should be a positive number"`, `"Chunked request with Content-Length header"`, `"Check maximum number of cookies"`, `"Check maximum number of parameters"`, `"Check maximum number of headers"`, `"Body in GET or HEAD requests"`, `"Bad multipart/form-data request parsing"`, `"Bad multipart parameters parsing"`, `"Bad HTTP version"`, `"Bad host header value"`. |
| `policy.blocking-settings.http-protocols[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.blocking-settings.http-protocols[].maxCookies` | `integer` | Numeric configuration value. |
| `policy.blocking-settings.http-protocols[].maxHeaders` | `integer` | Numeric configuration value. |
| `policy.blocking-settings.http-protocols[].maxParams` | `integer` | Numeric configuration value. |
| `policy.blocking-settings.violations` | `array` | List of configuration values. |
| `policy.blocking-settings.violations[].alarm` | `boolean` | Enable or disable this feature. |
| `policy.blocking-settings.violations[].block` | `boolean` | Enable or disable this feature. |
| `policy.blocking-settings.violations[].description` | `string` | String configuration value. |
| `policy.blocking-settings.violations[].name` | `string` | Allowed values: `"VIOL_ACCESS_INVALID"`, `"VIOL_ACCESS_MALFORMED"`, `"VIOL_ACCESS_MISSING"`, `"VIOL_ACCESS_UNAUTHORIZED"`, `"VIOL_ASM_COOKIE_HIJACKING"`, `"VIOL_ASM_COOKIE_MODIFIED"`, `"VIOL_BLACKLISTED_IP"`, `"VIOL_BOT_CLIENT"`, `"VIOL_BRUTE_FORCE"`, `"VIOL_COOKIE_EXPIRED"`, `"VIOL_COOKIE_LENGTH"`, `"VIOL_COOKIE_MALFORMED"`, `"VIOL_COOKIE_MODIFIED"`, `"VIOL_CSRF"`, `"VIOL_DATA_GUARD"`, `"VIOL_ENCODING"`, `"VIOL_EVASION"`, `"VIOL_FILE_UPLOAD"`, `"VIOL_FILE_UPLOAD_IN_BODY"`, `"VIOL_FILETYPE"`, `"VIOL_GEOLOCATION"`, `"VIOL_GRAPHQL_ERROR_RESPONSE"`, `"VIOL_GRAPHQL_FORMAT"`, `"VIOL_GRAPHQL_INTROSPECTION_QUERY"`, `"VIOL_GRAPHQL_MALFORMED"`, `"VIOL_GRPC_FORMAT"`, `"VIOL_GRPC_MALFORMED"`, `"VIOL_GRPC_METHOD"`, `"VIOL_HEADER_LENGTH"`, `"VIOL_HEADER_METACHAR"`, `"VIOL_HEADER_REPEATED"`, `"VIOL_HTTP_PROTOCOL"`, `"VIOL_HTTP_RESPONSE_STATUS"`, `"VIOL_JSON_FORMAT"`, `"VIOL_JSON_MALFORMED"`, `"VIOL_JSON_SCHEMA"`, `"VIOL_LOGIN"`, `"VIOL_LOGIN_URL_BYPASSED"`, `"VIOL_LOGIN_URL_EXPIRED"`, `"VIOL_MANDATORY_HEADER"`, `"VIOL_MANDATORY_PARAMETER"`, `"VIOL_MANDATORY_REQUEST_BODY"`, `"VIOL_METHOD"`, `"VIOL_PARAMETER"`, `"VIOL_PARAMETER_ARRAY_VALUE"`, `"VIOL_PARAMETER_DATA_TYPE"`, `"VIOL_PARAMETER_EMPTY_VALUE"`, `"VIOL_PARAMETER_LOCATION"`, `"VIOL_PARAMETER_MULTIPART_NULL_VALUE"`, `"VIOL_PARAMETER_NAME_METACHAR"`, `"VIOL_PARAMETER_NUMERIC_VALUE"`, `"VIOL_PARAMETER_REPEATED"`, `"VIOL_PARAMETER_STATIC_VALUE"`, `"VIOL_PARAMETER_VALUE_BASE64"`, `"VIOL_PARAMETER_VALUE_LENGTH"`, `"VIOL_PARAMETER_VALUE_METACHAR"`, `"VIOL_PARAMETER_VALUE_REGEXP"`, `"VIOL_POST_DATA_LENGTH"`, `"VIOL_QUERY_STRING_LENGTH"`, `"VIOL_RATING_NEED_EXAMINATION"`, `"VIOL_RATING_THREAT"`, `"VIOL_REQUEST_LENGTH"`, `"VIOL_REQUEST_MAX_LENGTH"`, `"VIOL_THREAT_CAMPAIGN"`, `"VIOL_URL"`, `"VIOL_URL_CONTENT_TYPE"`, `"VIOL_URL_LENGTH"`, `"VIOL_URL_METACHAR"`, `"VIOL_WEBSOCKET_BAD_REQUEST"`, `"VIOL_XML_FORMAT"`, `"VIOL_XML_MALFORMED"`. |
| `policy.blockingSettingReference` | `object` | Configuration object. |
| `policy.blockingSettingReference.link` | `string` | String configuration value. |
| `policy.bot-defense` | `object` | Configuration object. |
| `policy.bot-defense.mitigations` | `object` | Configuration object. |
| `policy.bot-defense.mitigations.anomalies` | `array` | List of configuration values. |
| `policy.bot-defense.mitigations.anomalies[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.bot-defense.mitigations.anomalies[].action` | `string` | Allowed values: `"alarm"`, `"block"`, `"default"`, `"detect"`, `"ignore"`. |
| `policy.bot-defense.mitigations.anomalies[].name` | `string` | String configuration value. |
| `policy.bot-defense.mitigations.anomalies[].scoreThreshold` | `string\|integer` | Configuration field. |
| `policy.bot-defense.mitigations.browsers` | `array` | List of configuration values. |
| `policy.bot-defense.mitigations.browsers[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.bot-defense.mitigations.browsers[].action` | `string` | Allowed values: `"alarm"`, `"block"`, `"detect"`. |
| `policy.bot-defense.mitigations.browsers[].maxVersion` | `integer` | Numeric configuration value. |
| `policy.bot-defense.mitigations.browsers[].minVersion` | `integer` | Numeric configuration value. |
| `policy.bot-defense.mitigations.browsers[].name` | `string` | String configuration value. |
| `policy.bot-defense.mitigations.classes` | `array` | List of configuration values. |
| `policy.bot-defense.mitigations.classes[].action` | `string` | Allowed values: `"alarm"`, `"block"`, `"detect"`, `"ignore"`. |
| `policy.bot-defense.mitigations.classes[].name` | `string` | Allowed values: `"browser"`, `"malicious-bot"`, `"suspicious-browser"`, `"trusted-bot"`, `"unknown"`, `"untrusted-bot"`. |
| `policy.bot-defense.mitigations.signatures` | `array` | List of configuration values. |
| `policy.bot-defense.mitigations.signatures[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.bot-defense.mitigations.signatures[].action` | `string` | Allowed values: `"alarm"`, `"block"`, `"detect"`, `"ignore"`. |
| `policy.bot-defense.mitigations.signatures[].name` | `string` | String configuration value. |
| `policy.bot-defense.settings` | `object` | Configuration object. |
| `policy.bot-defense.settings.caseSensitiveHttpHeaders` | `boolean` | Enable or disable this feature. |
| `policy.bot-defense.settings.isEnabled` | `boolean` | Enable or disable this feature. |
| `policy.browser-definitions` | `array` | List of configuration values. |
| `policy.browser-definitions[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.browser-definitions[].isUserDefined` | `boolean` | Enable or disable this feature. |
| `policy.browser-definitions[].matchRegex` | `string` | String configuration value. |
| `policy.browser-definitions[].matchString` | `string` | String configuration value. |
| `policy.browser-definitions[].name` | `string` | String configuration value. |
| `policy.caseInsensitive` | `boolean` | Enable or disable this feature. |
| `policy.character-sets` | `array` | List of configuration values. |
| `policy.character-sets[].characterSet` | `array` | List of configuration values. |
| `policy.character-sets[].characterSet[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.character-sets[].characterSet[].metachar` | `string` | String configuration value. |
| `policy.character-sets[].characterSetType` | `string` | Allowed values: `"gwt-content"`, `"header"`, `"json-content"`, `"parameter-name"`, `"parameter-value"`, `"plain-text-content"`, `"url"`, `"xml-content"`. |
| `policy.characterSetReference` | `object` | Configuration object. |
| `policy.characterSetReference.link` | `string` | String configuration value. |
| `policy.cookie-settings` | `object` | Configuration object. |
| `policy.cookie-settings.maximumCookieHeaderLength` | `string\|integer` | Configuration field. |
| `policy.cookieReference` | `object` | Configuration object. |
| `policy.cookieReference.link` | `string` | String configuration value. |
| `policy.cookieSettingsReference` | `object` | Configuration object. |
| `policy.cookieSettingsReference.link` | `string` | String configuration value. |
| `policy.cookies` | `array` | List of configuration values. |
| `policy.cookies[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.cookies[].accessibleOnlyThroughTheHttpProtocol` | `boolean` | Enable or disable this feature. |
| `policy.cookies[].attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.cookies[].decodeValueAsBase64` | `string` | Allowed values: `"enabled"`, `"disabled"`, `"required"`. |
| `policy.cookies[].enforcementType` | `string` | String configuration value. |
| `policy.cookies[].insertSameSiteAttribute` | `string` | Allowed values: `"lax"`, `"none"`, `"none-value"`, `"strict"`. |
| `policy.cookies[].maskValueInLogs` | `boolean` | Enable or disable this feature. |
| `policy.cookies[].name` | `string` | String configuration value. |
| `policy.cookies[].securedOverHttpsConnection` | `boolean` | Enable or disable this feature. |
| `policy.cookies[].signatureOverrides` | `array` | List of configuration values. |
| `policy.cookies[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.cookies[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.cookies[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.cookies[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.cookies[].type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.cookies[].wildcardOrder` | `integer` | Numeric configuration value. |
| `policy.csrf-protection` | `object` | Configuration object. |
| `policy.csrf-protection.enabled` | `boolean` | Enable or disable this feature. |
| `policy.csrf-protection.expirationTimeInSeconds` | `string` | String configuration value. |
| `policy.csrf-protection.sslOnly` | `boolean` | Enable or disable this feature. |
| `policy.csrf-urls` | `array` | List of configuration values. |
| `policy.csrf-urls[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.csrf-urls[].enforcementAction` | `string` | Allowed values: `"verify-origin"`, `"none"`. |
| `policy.csrf-urls[].method` | `string` | Allowed values: `"GET"`, `"POST"`, `"any"`. |
| `policy.csrf-urls[].url` | `string` | String configuration value. |
| `policy.csrf-urls[].wildcardOrder` | `integer` | Numeric configuration value. |
| `policy.data-guard` | `object` | Configuration object. |
| `policy.data-guard.creditCardNumbers` | `boolean` | Enable or disable this feature. |
| `policy.data-guard.customPatterns` | `boolean` | Enable or disable this feature. |
| `policy.data-guard.customPatternsList` | `array[string]` | Configuration field. |
| `policy.data-guard.enabled` | `boolean` | Enable or disable this feature. |
| `policy.data-guard.enforcementMode` | `string` | Allowed values: `"ignore-urls-in-list"`, `"enforce-urls-in-list"`. |
| `policy.data-guard.enforcementUrls` | `array[string]` | Configuration field. |
| `policy.data-guard.firstCustomCharactersToExpose` | `integer` | Numeric configuration value. |
| `policy.data-guard.lastCcnDigitsToExpose` | `integer` | Numeric configuration value. |
| `policy.data-guard.lastCustomCharactersToExpose` | `integer` | Numeric configuration value. |
| `policy.data-guard.lastSsnDigitsToExpose` | `integer` | Numeric configuration value. |
| `policy.data-guard.maskData` | `boolean` | Enable or disable this feature. |
| `policy.data-guard.usSocialSecurityNumbers` | `boolean` | Enable or disable this feature. |
| `policy.dataGuardReference` | `object` | Configuration object. |
| `policy.dataGuardReference.link` | `string` | String configuration value. |
| `policy.description` | `string` | String configuration value. |
| `policy.enablePassiveMode` | `boolean` | Enable or disable this feature. |
| `policy.enforcementMode` | `string` | Allowed values: `"transparent"`, `"blocking"`. |
| `policy.enforcer-settings` | `object` | Configuration object. |
| `policy.enforcer-settings.enforcerStateCookies` | `object` | Configuration object. |
| `policy.enforcer-settings.enforcerStateCookies.httpOnlyAttribute` | `boolean` | Enable or disable this feature. |
| `policy.enforcer-settings.enforcerStateCookies.sameSiteAttribute` | `string` | Allowed values: `"lax"`, `"none"`, `"none-value"`, `"strict"`. |
| `policy.enforcer-settings.enforcerStateCookies.secureAttribute` | `string` | Allowed values: `"always"`, `"never"`. |
| `policy.filetypeReference` | `object` | Configuration object. |
| `policy.filetypeReference.link` | `string` | String configuration value. |
| `policy.filetypes` | `array` | List of configuration values. |
| `policy.filetypes[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.filetypes[].allowed` | `boolean` | Enable or disable this feature. |
| `policy.filetypes[].checkPostDataLength` | `boolean` | Enable or disable this feature. |
| `policy.filetypes[].checkQueryStringLength` | `boolean` | Enable or disable this feature. |
| `policy.filetypes[].checkRequestLength` | `boolean` | Enable or disable this feature. |
| `policy.filetypes[].checkUrlLength` | `boolean` | Enable or disable this feature. |
| `policy.filetypes[].name` | `string` | String configuration value. |
| `policy.filetypes[].postDataLength` | `integer` | Numeric configuration value. |
| `policy.filetypes[].queryStringLength` | `integer` | Numeric configuration value. |
| `policy.filetypes[].requestLength` | `integer` | Numeric configuration value. |
| `policy.filetypes[].responseCheck` | `boolean` | Enable or disable this feature. |
| `policy.filetypes[].type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.filetypes[].urlLength` | `integer` | Numeric configuration value. |
| `policy.filetypes[].wildcardOrder` | `integer` | Numeric configuration value. |
| `policy.fullPath` | `string` | String configuration value. |
| `policy.general` | `object` | Configuration object. |
| `policy.general.allowedResponseCodes` | `array[integer]` | Configuration field. |
| `policy.general.customXffHeaders` | `array[string]` | Configuration field. |
| `policy.general.maskCreditCardNumbersInRequest` | `boolean` | Enable or disable this feature. |
| `policy.general.trustXff` | `boolean` | Enable or disable this feature. |
| `policy.generalReference` | `object` | Configuration object. |
| `policy.generalReference.link` | `string` | String configuration value. |
| `policy.disallowed-geolocations` | `array` | List of configuration values. |
| `policy.disallowed-geolocations[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.disallowed-geolocations[].countryCode` | `string` | Specifies the ISO country code of the selected country. Allowed values: `"AF"`, `"AX"`, `"AL"`, `"DZ"`, `"AS"`, `"AD"`, `"AO"`, `"AI"`, `"A1"`, `"AQ"`, `"AG"`, `"AR"`, `"AM"`, `"AW"`, `"AU"`, `"AT"`, `"AZ"`, `"BS"`, `"BH"`, `"BD"`, `"BB"`, `"BY"`, `"BE"`, `"BZ"`, `"BJ"`, `"BM"`, `"BT"`, `"BO"`, `"BA"`, `"BW"`, `"BV"`, `"BR"`, `"IO"`, `"BN"`, `"BG"`, `"BF"`, `"BI"`, `"KH"`, `"CM"`, `"CA"`, `"CV"`, `"KY"`, `"CF"`, `"TD"`, `"CL"`, `"CN"`, `"CX"`, `"CC"`, `"CO"`, `"KM"`, `"CG"`, `"CD"`, `"CK"`, `"CR"`, `"CI"`, `"HR"`, `"CU"`, `"CY"`, `"CZ"`, `"DK"`, `"DJ"`, `"DM"`, `"DO"`, `"EC"`, `"EG"`, `"SV"`, `"GQ"`, `"ER"`, `"EE"`, `"ET"`, `"FK"`, `"FO"`, `"FJ"`, `"FI"`, `"FR"`, `"FX"`, `"GF"`, `"PF"`, `"TF"`, `"GA"`, `"GM"`, `"GE"`, `"DE"`, `"GH"`, `"GI"`, `"GR"`, `"GL"`, `"GD"`, `"GP"`, `"GU"`, `"GT"`, `"GG"`, `"GN"`, `"GW"`, `"GY"`, `"HT"`, `"HM"`, `"VA"`, `"HN"`, `"HK"`, `"HU"`, `"IS"`, `"IN"`, `"ID"`, `"IR"`, `"IQ"`, `"IE"`, `"IM"`, `"IL"`, `"IT"`, `"JM"`, `"JP"`, `"JE"`, `"JO"`, `"KZ"`, `"KE"`, `"KI"`, `"KP"`, `"KR"`, `"KW"`, `"KG"`, `"LA"`, `"LV"`, `"LB"`, `"LS"`, `"LR"`, `"LY"`, `"LI"`, `"LT"`, `"LU"`, `"MO"`, `"MK"`, `"MG"`, `"MW"`, `"MY"`, `"MV"`, `"ML"`, `"MT"`, `"MH"`, `"MQ"`, `"MR"`, `"MU"`, `"YT"`, `"MX"`, `"FM"`, `"MD"`, `"MC"`, `"MN"`, `"ME"`, `"MS"`, `"MA"`, `"MZ"`, `"MM"`, `"ZZ"`, `"NA"`, `"NR"`, `"NP"`, `"NL"`, `"AN"`, `"NC"`, `"NZ"`, `"NI"`, `"NE"`, `"NG"`, `"NU"`, `"NF"`, `"MP"`, `"NO"`, `"OM"`, `"PK"`, `"PW"`, `"PS"`, `"PA"`, `"PG"`, `"PY"`, `"PE"`, `"PH"`, `"PN"`, `"PL"`, `"PT"`, `"PR"`, `"QA"`, `"RE"`, `"RO"`, `"RU"`, `"RW"`, `"BL"`, `"SH"`, `"KN"`, `"LC"`, `"MF"`, `"PM"`, `"VC"`, `"WS"`, `"SM"`, `"ST"`, `"A2"`, `"SA"`, `"SN"`, `"RS"`, `"SC"`, `"SL"`, `"SG"`, `"SK"`, `"SI"`, `"SB"`, `"SO"`, `"ZA"`, `"GS"`, `"ES"`, `"LK"`, `"SD"`, `"SR"`, `"SJ"`, `"SZ"`, `"SE"`, `"CH"`, `"SY"`, `"TW"`, `"TJ"`, `"TZ"`, `"TH"`, `"TL"`, `"TG"`, `"TK"`, `"TO"`, `"TT"`, `"TN"`, `"TR"`, `"TM"`, `"TC"`, `"TV"`, `"UG"`, `"UA"`, `"AE"`, `"GB"`, `"US"`, `"UM"`, `"UY"`, `"UZ"`, `"VU"`, `"VE"`, `"VN"`, `"VG"`, `"VI"`, `"WF"`, `"EH"`, `"YE"`, `"ZM"`, `"ZW"`. |
| `policy.disallowed-geolocations[].countryName` | `string` | Specifies the name of the country. Allowed values: `"Afghanistan", "Aland Islands", "Albania", "Algeria", "American Samoa", "Andorra", "Angola", "Anguilla", "Anonymous Proxy", "Antarctica", "Antigua and Barbuda", "Argentina", "Armenia", "Aruba", "Australia", "Austria", "Azerbaijan", "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bermuda", "Bhutan", "Bolivia", "Bosnia and Herzegovina", "Botswana", "Bouvet Island", "Brazil", "British Indian Ocean Territory", "Brunei Darussalam", "Bulgaria", "Burkina Faso", "Burundi", "Cambodia", "Cameroon", "Canada", "Cape Verde", "Cayman Islands", "Central African Republic", "Chad", "Chile", "China", "Christmas Island", "Cocos (Keeling) Islands", "Colombia", "Comoros", "Congo", "Congo, The Democratic Republic of the", "Cook Islands", "Costa Rica", "Cote D'Ivoire", "Croatia", "Cuba", "Cyprus", "Czech Republic", "Denmark", "Djibouti", "Dominica", "Dominican Republic", "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Ethiopia", "Falkland Islands (Malvinas)", "Faroe Islands", "Fiji", "Finland", "France", "France, Metropolitan", "French Guiana", "French Polynesia", "French Southern Territories", "Gabon", "Gambia", "Georgia", "Germany", "Ghana", "Gibraltar", "Greece", "Greenland", "Grenada", "Guadeloupe", "Guam", "Guatemala", "Guernsey", "Guinea", "Guinea-Bissau", "Guyana", "Haiti", "Heard Island and McDonald Islands", "Holy See (Vatican City State)", "Honduras", "Hong Kong", "Hungary", "Iceland", "India", "Indonesia", "Iran, Islamic Republic of", "Iraq", "Ireland", "Isle of Man", "Israel", "Italy", "Jamaica", "Japan", "Jersey", "Jordan", "Kazakhstan", "Kenya", "Kiribati", "Korea, Democratic People's Republic of", "Korea, Republic of", "Kuwait", "Kyrgyzstan", "Lao People's Democratic Republic", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libyan Arab Jamahiriya", "Liechtenstein", "Lithuania", "Luxembourg", "Macau", "Macedonia", "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", "Marshall Islands", "Martinique", "Mauritania", "Mauritius", "Mayotte", "Mexico", "Micronesia, Federated States of", "Moldova, Republic of", "Monaco", "Mongolia", "Montenegro", "Montserrat", "Morocco", "Mozambique", "Myanmar", "N/A", "Namibia", "Nauru", "Nepal", "Netherlands", "Netherlands Antilles", "New Caledonia", "New Zealand", "Nicaragua", "Niger", "Nigeria", "Niue", "Norfolk Island", "Northern Mariana Islands", "Norway", "Oman", "Other", "Pakistan", "Palau", "Palestinian Territory", "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", "Pitcairn Islands", "Poland", "Portugal", "Puerto Rico", "Qatar", "Reunion", "Romania", "Russian Federation", "Rwanda", "Saint Barthelemy", "Saint Helena", "Saint Kitts and Nevis", "Saint Lucia", "Saint Martin", "Saint Pierre and Miquelon", "Saint Vincent and the Grenadines", "Samoa", "San Marino", "Sao Tome and Principe", "Satellite Provider", "Saudi Arabia", "Senegal", "Serbia", "Seychelles", "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa", "South Georgia and the South Sandwich Islands", "Spain", "Sri Lanka", "Sudan", "Suriname", "Svalbard and Jan Mayen", "Swaziland", "Sweden", "Switzerland", "Syrian Arab Republic", "Taiwan", "Tajikistan", "Tanzania, United Republic of", "Thailand", "Timor-Leste", "Togo", "Tokelau", "Tonga", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Turks and Caicos Islands", "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom", "United States", "United States Minor Outlying Islands", "Uruguay", "Uzbekistan", "Vanuatu", "Venezuela", "Vietnam", "Virgin Islands, British", "Virgin Islands, U.S.", "Wallis and Futuna", "Western Sahara", "Yemen", "Zambia", "Zimbabwe"` |
| `policy.disallowedGeolocationReference` | `object` | Configuration object. |
| `policy.disallowedGeolocationReference.link` | `string` | String configuration value. |
| `policy.graphql-profiles` | `array` | List of configuration values. |
| `policy.graphql-profiles[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.graphql-profiles[].attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.graphql-profiles[].defenseAttributes` | `object` | Configuration object. |
| `policy.graphql-profiles[].defenseAttributes.allowIntrospectionQueries` | `boolean` | Enable or disable this feature. |
| `policy.graphql-profiles[].defenseAttributes.maximumBatchedQueries` | `string\|integer` | Configuration field. |
| `policy.graphql-profiles[].defenseAttributes.maximumQueryCost` | `string\|integer` | Configuration field. |
| `policy.graphql-profiles[].defenseAttributes.maximumStructureDepth` | `string\|integer` | Configuration field. |
| `policy.graphql-profiles[].defenseAttributes.maximumTotalLength` | `string\|integer` | Configuration field. |
| `policy.graphql-profiles[].defenseAttributes.maximumValueLength` | `string\|integer` | Configuration field. |
| `policy.graphql-profiles[].defenseAttributes.tolerateParsingWarnings` | `boolean` | Enable or disable this feature. |
| `policy.graphql-profiles[].description` | `string` | String configuration value. |
| `policy.graphql-profiles[].metacharElementCheck` | `boolean` | Enable or disable this feature. |
| `policy.graphql-profiles[].metacharOverrides` | `array` | List of configuration values. |
| `policy.graphql-profiles[].metacharOverrides[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.graphql-profiles[].metacharOverrides[].metachar` | `string` | String configuration value. |
| `policy.graphql-profiles[].name` | `string` | String configuration value. |
| `policy.graphql-profiles[].responseEnforcement` | `object` | Configuration object. |
| `policy.graphql-profiles[].responseEnforcement.blockDisallowedPatterns` | `boolean` | Enable or disable this feature. |
| `policy.graphql-profiles[].responseEnforcement.disallowedPatterns` | `array[string]` | Configuration field. |
| `policy.graphql-profiles[].sensitiveData` | `array` | List of configuration values. |
| `policy.graphql-profiles[].sensitiveData[].parameterName` | `string` | String configuration value. |
| `policy.graphql-profiles[].signatureOverrides` | `array` | List of configuration values. |
| `policy.graphql-profiles[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.graphql-profiles[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.graphql-profiles[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.graphql-profiles[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.grpc-profiles` | `array` | List of configuration values. |
| `policy.grpc-profiles[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.grpc-profiles[].associateUrls` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].decodeStringValuesAsBase64` | `string` | Allowed values: `"disabled"`, `"enabled"`. |
| `policy.grpc-profiles[].defenseAttributes` | `object` | Configuration object. |
| `policy.grpc-profiles[].defenseAttributes.allowUnknownFields` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].defenseAttributes.maximumDataLength` | `string\|integer` | Configuration field. |
| `policy.grpc-profiles[].description` | `string` | String configuration value. |
| `policy.grpc-profiles[].hasIdlFiles` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].idlFiles` | `array` | List of configuration values. |
| `policy.grpc-profiles[].idlFiles[].idlFile` | `object` | Configuration object. |
| `policy.grpc-profiles[].idlFiles[].idlFile.contents` | `string` | String configuration value. |
| `policy.grpc-profiles[].idlFiles[].idlFile.fileName` | `string` | String configuration value. |
| `policy.grpc-profiles[].idlFiles[].idlFile.isBase64` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].idlFiles[].importUrl` | `string` | String configuration value. |
| `policy.grpc-profiles[].idlFiles[].isPrimary` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].idlFiles[].primaryIdlFileName` | `string` | String configuration value. |
| `policy.grpc-profiles[].metacharCheck` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].metacharElementCheck` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].name` | `string` | String configuration value. |
| `policy.grpc-profiles[].signatureOverrides` | `array` | List of configuration values. |
| `policy.grpc-profiles[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.grpc-profiles[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.grpc-profiles[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.grpc-profiles[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.header-settings` | `object` | Configuration object. |
| `policy.header-settings.maximumHttpHeaderLength` | `string\|integer` | Configuration field. |
| `policy.headerReference` | `object` | Configuration object. |
| `policy.headerReference.link` | `string` | String configuration value. |
| `policy.headerSettingsReference` | `object` | Configuration object. |
| `policy.headerSettingsReference.link` | `string` | String configuration value. |
| `policy.headers` | `array` | List of configuration values. |
| `policy.headers[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.headers[].allowRepeatedOccurrences` | `boolean` | Enable or disable this feature. |
| `policy.headers[].base64Decoding` | `boolean` | Enable or disable this feature. |
| `policy.headers[].checkSignatures` | `boolean` | Enable or disable this feature. |
| `policy.headers[].decodeValueAsBase64` | `string` | Allowed values: `"enabled"`, `"disabled"`, `"required"`. |
| `policy.headers[].htmlNormalization` | `boolean` | Enable or disable this feature. |
| `policy.headers[].mandatory` | `boolean` | Enable or disable this feature. |
| `policy.headers[].maskValueInLogs` | `boolean` | Enable or disable this feature. |
| `policy.headers[].name` | `string` | String configuration value. |
| `policy.headers[].normalizationViolations` | `boolean` | Enable or disable this feature. |
| `policy.headers[].percentDecoding` | `boolean` | Enable or disable this feature. |
| `policy.headers[].signatureOverrides` | `array` | List of configuration values. |
| `policy.headers[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.headers[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.headers[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.headers[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.headers[].type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.headers[].urlNormalization` | `boolean` | Enable or disable this feature. |
| `policy.headers[].wildcardOrder` | `integer` | Numeric configuration value. |
| `policy.host-names` | `array` | List of configuration values. |
| `policy.host-names[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.host-names[].includeSubdomains` | `boolean` | Enable or disable this feature. |
| `policy.host-names[].name` | `string` | String configuration value. |
| `policy.idl-files` | `array` | List of configuration values. |
| `policy.idl-files[].contents` | `string` | String configuration value. |
| `policy.idl-files[].fileName` | `string` | String configuration value. |
| `policy.idl-files[].isBase64` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles` | `array` | List of configuration values. |
| `policy.json-profiles[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.json-profiles[].attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles[].defenseAttributes` | `object` | Configuration object. |
| `policy.json-profiles[].defenseAttributes.maximumArrayLength` | `string\|integer` | Configuration field. |
| `policy.json-profiles[].defenseAttributes.maximumStructureDepth` | `string\|integer` | Configuration field. |
| `policy.json-profiles[].defenseAttributes.maximumTotalLengthOfJSONData` | `string\|integer` | Configuration field. |
| `policy.json-profiles[].defenseAttributes.maximumValueLength` | `string\|integer` | Configuration field. |
| `policy.json-profiles[].defenseAttributes.tolerateJSONParsingWarnings` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles[].description` | `string` | String configuration value. |
| `policy.json-profiles[].handleJsonValuesAsParameters` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles[].hasValidationFiles` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles[].metacharOverrides` | `array` | List of configuration values. |
| `policy.json-profiles[].metacharOverrides[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles[].metacharOverrides[].metachar` | `string` | String configuration value. |
| `policy.json-profiles[].name` | `string` | String configuration value. |
| `policy.json-profiles[].signatureOverrides` | `array` | List of configuration values. |
| `policy.json-profiles[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.json-profiles[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.json-profiles[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.json-profiles[].validationFiles` | `array` | List of configuration values. |
| `policy.json-profiles[].validationFiles[].importUrl` | `string` | String configuration value. |
| `policy.json-profiles[].validationFiles[].isPrimary` | `boolean` | Enable or disable this feature. |
| `policy.json-profiles[].validationFiles[].jsonValidationFile` | `object` | Configuration object. |
| `policy.json-profiles[].validationFiles[].jsonValidationFile.$action` | `string` | Allowed values: `"delete"`. |
| `policy.json-profiles[].validationFiles[].jsonValidationFile.contents` | `string` | String configuration value. |
| `policy.json-profiles[].validationFiles[].jsonValidationFile.fileName` | `string` | String configuration value. |
| `policy.json-profiles[].validationFiles[].jsonValidationFile.isBase64` | `boolean` | Enable or disable this feature. |
| `policy.json-validation-files` | `array` | List of configuration values. |
| `policy.json-validation-files[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.json-validation-files[].contents` | `string` | String configuration value. |
| `policy.json-validation-files[].fileName` | `string` | String configuration value. |
| `policy.json-validation-files[].isBase64` | `boolean` | Enable or disable this feature. |
| `policy.jsonProfileReference` | `object` | Configuration object. |
| `policy.jsonProfileReference.link` | `string` | String configuration value. |
| `policy.jsonValidationFileReference` | `object` | Configuration object. |
| `policy.jsonValidationFileReference.link` | `string` | String configuration value. |
| `policy.methodReference` | `object` | Configuration object. |
| `policy.methodReference.link` | `string` | String configuration value. |
| `policy.methods` | `array` | List of configuration values. |
| `policy.methods[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.methods[].name` | `string` | String configuration value. |
| `policy.name` | `string` | String configuration value. |
| `policy.open-api-files` | `array` | List of configuration values. |
| `policy.open-api-files[].link` | `string` | String configuration value. |
| `policy.parameterReference` | `object` | Configuration object. |
| `policy.parameterReference.link` | `string` | String configuration value. |
| `policy.parameters` | `array` | List of configuration values. |
| `policy.parameters[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.parameters[].allowEmptyValue` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].allowRepeatedParameterName` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].arraySerializationFormat` | `string` | Allowed values: `"csv"`, `"form"`, `"label"`, `"matrix"`, `"multi"`, `"multipart"`, `"pipe"`, `"ssv"`, `"tsv"`. |
| `policy.parameters[].attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].checkMaxValue` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].checkMaxValueLength` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].checkMetachars` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].checkMinValue` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].checkMinValueLength` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].checkMultipleOfValue` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].contentProfile` | `object` | Configuration object. |
| `policy.parameters[].contentProfile.name` | `string` | String configuration value. |
| `policy.parameters[].dataType` | `string` | Allowed values: `"alpha-numeric"`, `"binary"`, `"boolean"`, `"decimal"`, `"email"`, `"integer"`, `"none"`, `"phone"`. |
| `policy.parameters[].decodeValueAsBase64` | `string` | Allowed values: `"enabled"`, `"disabled"`, `"required"`. |
| `policy.parameters[].disallowFileUploadOfExecutables` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].enableRegularExpression` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].exclusiveMax` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].exclusiveMin` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].isBase64` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].isCookie` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].isHeader` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].level` | `string` | Allowed values: `"global"`, `"url"`. |
| `policy.parameters[].mandatory` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].maximumLength` | `integer` | Numeric configuration value. |
| `policy.parameters[].maximumValue` | `integer` | Numeric configuration value. |
| `policy.parameters[].metacharsOnParameterValueCheck` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].minimumLength` | `integer` | Numeric configuration value. |
| `policy.parameters[].minimumValue` | `integer` | Numeric configuration value. |
| `policy.parameters[].multipleOf` | `integer` | Numeric configuration value. |
| `policy.parameters[].name` | `string` | String configuration value. |
| `policy.parameters[].nameMetacharOverrides` | `array` | List of configuration values. |
| `policy.parameters[].nameMetacharOverrides[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].nameMetacharOverrides[].metachar` | `string` | String configuration value. |
| `policy.parameters[].objectSerializationStyle` | `string` | String configuration value. |
| `policy.parameters[].parameterEnumValues` | `array[string]` | Configuration field. |
| `policy.parameters[].parameterLocation` | `string` | Allowed values: `"any"`, `"cookie"`, `"form-data"`, `"header"`, `"path"`, `"query"`. |
| `policy.parameters[].regularExpression` | `string` | String configuration value. |
| `policy.parameters[].sensitiveParameter` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].signatureOverrides` | `array` | List of configuration values. |
| `policy.parameters[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.parameters[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.parameters[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.parameters[].staticValues` | `string` | String configuration value. |
| `policy.parameters[].type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.parameters[].url` | `object` | Configuration object. |
| `policy.parameters[].url.method` | `string` | Allowed values: `"ACL"`, `"BCOPY"`, `"BDELETE"`, `"BMOVE"`, `"BPROPFIND"`, `"BPROPPATCH"`, `"CHECKIN"`, `"CHECKOUT"`, `"CONNECT"`, `"COPY"`, `"DELETE"`, `"GET"`, `"HEAD"`, `"LINK"`, `"LOCK"`, `"MERGE"`, `"MKCOL"`, `"MKWORKSPACE"`, `"MOVE"`, `"NOTIFY"`, `"OPTIONS"`, `"PATCH"`, `"POLL"`, `"POST"`, `"PROPFIND"`, `"PROPPATCH"`, `"PUT"`, `"REPORT"`, `"RPC_IN_DATA"`, `"RPC_OUT_DATA"`, `"SEARCH"`, `"SUBSCRIBE"`, `"TRACE"`, `"TRACK"`, `"UNLINK"`, `"UNLOCK"`, `"UNSUBSCRIBE"`, `"VERSION_CONTROL"`, `"X-MS-ENUMATTS"`, `"*"`. |
| `policy.parameters[].url.name` | `string` | String configuration value. |
| `policy.parameters[].url.protocol` | `string` | Allowed values: `"http"`, `"https"`. |
| `policy.parameters[].url.type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.parameters[].valueMetacharOverrides` | `array` | List of configuration values. |
| `policy.parameters[].valueMetacharOverrides[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.parameters[].valueMetacharOverrides[].metachar` | `string` | String configuration value. |
| `policy.parameters[].valueType` | `string` | Allowed values: `"array"`, `"auto-detect"`, `"dynamic-content"`, `"dynamic-parameter-name"`, `"ignore"`, `"json"`, `"object"`, `"openapi-array"`, `"static-content"`, `"user-input"`, `"xml"`. |
| `policy.parameters[].wildcardOrder` | `integer` | Numeric configuration value. |
| `policy.response-pages` | `array` | List of configuration values. |
| `policy.response-pages[].ajaxActionType` | `string` | Allowed values: `"alert-popup"`, `"custom"`, `"redirect"`. |
| `policy.response-pages[].ajaxCustomContent` | `string` | String configuration value. |
| `policy.response-pages[].ajaxEnabled` | `boolean` | Enable or disable this feature. |
| `policy.response-pages[].ajaxPopupMessage` | `string` | String configuration value. |
| `policy.response-pages[].ajaxRedirectUrl` | `string` | String configuration value. |
| `policy.response-pages[].grpcStatusCode` | `string` | String configuration value. |
| `policy.response-pages[].grpcStatusMessage` | `string` | String configuration value. |
| `policy.response-pages[].responseActionType` | `string` | Allowed values: `"custom"`, `"default"`, `"erase-cookies"`, `"redirect"`, `"soap-fault"`. |
| `policy.response-pages[].responseContent` | `string` | String configuration value. |
| `policy.response-pages[].responseHeader` | `string` | String configuration value. |
| `policy.response-pages[].responsePageType` | `string` | Allowed values: `"ajax"`, `"ajax-login"`, `"captcha"`, `"captcha-fail"`, `"default"`, `"failed-login-honeypot"`, `"failed-login-honeypot-ajax"`, `"hijack"`, `"leaked-credentials"`, `"leaked-credentials-ajax"`, `"mobile"`, `"persistent-flow"`, `"xml"`, `"grpc"`. |
| `policy.response-pages[].responseRedirectUrl` | `string` | String configuration value. |
| `policy.responsePageReference` | `object` | Configuration object. |
| `policy.responsePageReference.link` | `string` | String configuration value. |
| `policy.sensitive-parameters` | `array` | List of configuration values. |
| `policy.sensitive-parameters[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.sensitive-parameters[].name` | `string` | String configuration value. |
| `policy.sensitiveParameterReference` | `object` | Configuration object. |
| `policy.sensitiveParameterReference.link` | `string` | String configuration value. |
| `policy.server-technologies` | `array` | List of configuration values. |
| `policy.server-technologies[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.server-technologies[].serverTechnologyName` | `string` | Allowed values: `"Jenkins"`, `"SharePoint"`, `"Oracle Application Server"`, `"Python"`, `"Oracle Identity Manager"`, `"Spring Boot"`, `"CouchDB"`, `"SQLite"`, `"Handlebars"`, `"Mustache"`, `"Prototype"`, `"Zend"`, `"Redis"`, `"Underscore.js"`, `"Ember.js"`, `"ZURB Foundation"`, `"ef.js"`, `"Vue.js"`, `"UIKit"`, `"TYPO3 CMS"`, `"RequireJS"`, `"React"`, `"MooTools"`, `"Laravel"`, `"GraphQL"`, `"Google Web Toolkit"`, `"Express.js"`, `"CodeIgniter"`, `"Backbone.js"`, `"AngularJS"`, `"JavaScript"`, `"Nginx"`, `"Jetty"`, `"Joomla"`, `"JavaServer Faces (JSF)"`, `"Ruby"`, `"MongoDB"`, `"Django"`, `"Node.js"`, `"Citrix"`, `"JBoss"`, `"Elasticsearch"`, `"Apache Struts"`, `"XML"`, `"PostgreSQL"`, `"IBM DB2"`, `"Sybase/ASE"`, `"CGI"`, `"Proxy Servers"`, `"SSI (Server Side Includes)"`, `"Cisco"`, `"Novell"`, `"Macromedia JRun"`, `"BEA Systems WebLogic Server"`, `"Lotus Domino"`, `"MySQL"`, `"Oracle"`, `"Microsoft SQL Server"`, `"PHP"`, `"Outlook Web Access"`, `"Apache/NCSA HTTP Server"`, `"Apache Tomcat"`, `"WordPress"`, `"Macromedia ColdFusion"`, `"Unix/Linux"`, `"Microsoft Windows"`, `"ASP.NET"`, `"Front Page Server Extensions (FPSE)"`, `"IIS"`, `"WebDAV"`, `"ASP"`, `"Java Servlets/JSP"`, `"jQuery"`. |
| `policy.serverTechnologyReference` | `object` | Configuration object. |
| `policy.serverTechnologyReference.link` | `string` | String configuration value. |
| `policy.signature-requirements` | `array` | List of configuration values. |
| `policy.signature-requirements[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.signature-requirements[].tag` | `string` | String configuration value. |
| `policy.signature-sets` | `array` | List of configuration values. |
| `policy.signature-sets[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.signature-sets[].alarm` | `boolean` | Enable or disable this feature. |
| `policy.signature-sets[].block` | `boolean` | Enable or disable this feature. |
| `policy.signature-sets[].name` | `string` | String configuration value. |
| `policy.signature-settings` | `object` | Configuration object. |
| `policy.signature-settings.attackSignatureFalsePositiveMode` | `string` | Allowed values: `"detect"`, `"detect-and-allow"`, `"disabled"`. |
| `policy.signature-settings.minimumAccuracyForAutoAddedSignatures` | `string` | Allowed values: `"high"`, `"low"`, `"medium"`. |
| `policy.signatureReference` | `object` | Configuration object. |
| `policy.signatureReference.link` | `string` | String configuration value. |
| `policy.signatureSetReference` | `object` | Configuration object. |
| `policy.signatureSetReference.link` | `string` | String configuration value. |
| `policy.signatureSettingReference` | `object` | Configuration object. |
| `policy.signatureSettingReference.link` | `string` | String configuration value. |
| `policy.signatures` | `array` | List of configuration values. |
| `policy.signatures[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.signatures[].name` | `string` | String configuration value. |
| `policy.signatures[].signatureId` | `integer` | Numeric configuration value. |
| `policy.signatures[].tag` | `string` | String configuration value. |
| `policy.softwareVersion` | `string` | String configuration value. |
| `policy.template` | `object` | Configuration object. |
| `policy.template.name` | `string` | String configuration value. |
| `policy.threat-campaigns` | `array` | List of configuration values. |
| `policy.threat-campaigns[].isEnabled` | `boolean` | Enable or disable this feature. |
| `policy.threat-campaigns[].name` | `string` | String configuration value. |
| `policy.threatCampaignReference` | `object` | Configuration object. |
| `policy.threatCampaignReference.link` | `string` | String configuration value. |
| `policy.urlReference` | `object` | Configuration object. |
| `policy.urlReference.link` | `string` | String configuration value. |
| `policy.urls` | `array` | List of configuration values. |
| `policy.urls[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.urls[].allowRenderingInFrames` | `string` | Allowed values: `"never"`, `"only-same"`. |
| `policy.urls[].allowRenderingInFramesOnlyFrom` | `string` | String configuration value. |
| `policy.urls[].attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.urls[].clickjackingProtection` | `boolean` | Enable or disable this feature. |
| `policy.urls[].description` | `string` | String configuration value. |
| `policy.urls[].disallowFileUploadOfExecutables` | `boolean` | Enable or disable this feature. |
| `policy.urls[].html5CrossOriginRequestsEnforcement` | `object` | Configuration object. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.allowOriginsEnforcementMode` | `string` | Allowed values: `"replace-with"`, `"unmodified"`. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.checkAllowedMethods` | `boolean` | Enable or disable this feature. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.crossDomainAllowedOrigin` | `array` | List of configuration values. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.crossDomainAllowedOrigin[].includeSubDomains` | `boolean` | Enable or disable this feature. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.crossDomainAllowedOrigin[].originName` | `string` | String configuration value. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.crossDomainAllowedOrigin[].originPort` | `string\|integer` | Configuration field. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.crossDomainAllowedOrigin[].originProtocol` | `string` | Allowed values: `"http"`, `"http/https"`, `"https"`. |
| `policy.urls[].html5CrossOriginRequestsEnforcement.enforcementMode` | `string` | Allowed values: `"disabled"`, `"enforce"`. |
| `policy.urls[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.urls[].mandatoryBody` | `boolean` | Enable or disable this feature. |
| `policy.urls[].metacharOverrides` | `array` | List of configuration values. |
| `policy.urls[].metacharOverrides[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.urls[].metacharOverrides[].metachar` | `string` | String configuration value. |
| `policy.urls[].metacharsOnUrlCheck` | `boolean` | Enable or disable this feature. |
| `policy.urls[].method` | `string` | Allowed values: `"ACL"`, `"BCOPY"`, `"BDELETE"`, `"BMOVE"`, `"BPROPFIND"`, `"BPROPPATCH"`, `"CHECKIN"`, `"CHECKOUT"`, `"CONNECT"`, `"COPY"`, `"DELETE"`, `"GET"`, `"HEAD"`, `"LINK"`, `"LOCK"`, `"MERGE"`, `"MKCOL"`, `"MKWORKSPACE"`, `"MOVE"`, `"NOTIFY"`, `"OPTIONS"`, `"PATCH"`, `"POLL"`, `"POST"`, `"PROPFIND"`, `"PROPPATCH"`, `"PUT"`, `"REPORT"`, `"RPC_IN_DATA"`, `"RPC_OUT_DATA"`, `"SEARCH"`, `"SUBSCRIBE"`, `"TRACE"`, `"TRACK"`, `"UNLINK"`, `"UNLOCK"`, `"UNSUBSCRIBE"`, `"VERSION_CONTROL"`, `"X-MS-ENUMATTS"`, `"*"`. |
| `policy.urls[].methodOverrides` | `array` | List of configuration values. |
| `policy.urls[].methodOverrides[].allowed` | `boolean` | Enable or disable this feature. |
| `policy.urls[].methodOverrides[].method` | `string` | Allowed values: `"ACL"`, `"BCOPY"`, `"BDELETE"`, `"BMOVE"`, `"BPROPFIND"`, `"BPROPPATCH"`, `"CHECKIN"`, `"CHECKOUT"`, `"CONNECT"`, `"COPY"`, `"DELETE"`, `"GET"`, `"HEAD"`, `"LINK"`, `"LOCK"`, `"MERGE"`, `"MKCOL"`, `"MKWORKSPACE"`, `"MOVE"`, `"NOTIFY"`, `"OPTIONS"`, `"PATCH"`, `"POLL"`, `"POST"`, `"PROPFIND"`, `"PROPPATCH"`, `"PUT"`, `"REPORT"`, `"RPC_IN_DATA"`, `"RPC_OUT_DATA"`, `"SEARCH"`, `"SUBSCRIBE"`, `"TRACE"`, `"TRACK"`, `"UNLINK"`, `"UNLOCK"`, `"UNSUBSCRIBE"`, `"VERSION_CONTROL"`, `"X-MS-ENUMATTS"`. |
| `policy.urls[].methodsOverrideOnUrlCheck` | `boolean` | Enable or disable this feature. |
| `policy.urls[].name` | `string` | String configuration value. |
| `policy.urls[].operationId` | `string` | String configuration value. |
| `policy.urls[].positionalParameters` | `array` | List of configuration values. |
| `policy.urls[].positionalParameters[].parameter` | `object` | Configuration object. |
| `policy.urls[].positionalParameters[].parameter.$action` | `string` | Allowed values: `"delete"`. |
| `policy.urls[].positionalParameters[].parameter.allowEmptyValue` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.allowRepeatedParameterName` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.arraySerializationFormat` | `string` | Allowed values: `"csv"`, `"form"`, `"label"`, `"matrix"`, `"multi"`, `"multipart"`, `"pipe"`, `"ssv"`, `"tsv"`. |
| `policy.urls[].positionalParameters[].parameter.attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.checkMaxValue` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.checkMaxValueLength` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.checkMetachars` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.checkMinValue` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.checkMinValueLength` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.checkMultipleOfValue` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.contentProfile` | `object` | Configuration object. |
| `policy.urls[].positionalParameters[].parameter.contentProfile.name` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.dataType` | `string` | Allowed values: `"alpha-numeric"`, `"binary"`, `"boolean"`, `"decimal"`, `"email"`, `"integer"`, `"none"`, `"phone"`. |
| `policy.urls[].positionalParameters[].parameter.decodeValueAsBase64` | `string` | Allowed values: `"enabled"`, `"disabled"`, `"required"`. |
| `policy.urls[].positionalParameters[].parameter.disallowFileUploadOfExecutables` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.enableRegularExpression` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.exclusiveMax` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.exclusiveMin` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.isBase64` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.isCookie` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.isHeader` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.level` | `string` | Allowed values: `"global"`, `"url"`. |
| `policy.urls[].positionalParameters[].parameter.mandatory` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.maximumLength` | `integer` | Numeric configuration value. |
| `policy.urls[].positionalParameters[].parameter.maximumValue` | `integer` | Numeric configuration value. |
| `policy.urls[].positionalParameters[].parameter.metacharsOnParameterValueCheck` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.minimumLength` | `integer` | Numeric configuration value. |
| `policy.urls[].positionalParameters[].parameter.minimumValue` | `integer` | Numeric configuration value. |
| `policy.urls[].positionalParameters[].parameter.multipleOf` | `integer` | Numeric configuration value. |
| `policy.urls[].positionalParameters[].parameter.name` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.nameMetacharOverrides` | `array` | List of configuration values. |
| `policy.urls[].positionalParameters[].parameter.nameMetacharOverrides[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.nameMetacharOverrides[].metachar` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.objectSerializationStyle` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.parameterEnumValues` | `array[string]` | Configuration field. |
| `policy.urls[].positionalParameters[].parameter.parameterLocation` | `string` | Allowed values: `"any"`, `"cookie"`, `"form-data"`, `"header"`, `"path"`, `"query"`. |
| `policy.urls[].positionalParameters[].parameter.regularExpression` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.sensitiveParameter` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.signatureOverrides` | `array` | List of configuration values. |
| `policy.urls[].positionalParameters[].parameter.signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.signatureOverrides[].name` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.urls[].positionalParameters[].parameter.signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.staticValues` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.urls[].positionalParameters[].parameter.url` | `object` | Configuration object. |
| `policy.urls[].positionalParameters[].parameter.url.method` | `string` | Allowed values: `"ACL"`, `"BCOPY"`, `"BDELETE"`, `"BMOVE"`, `"BPROPFIND"`, `"BPROPPATCH"`, `"CHECKIN"`, `"CHECKOUT"`, `"CONNECT"`, `"COPY"`, `"DELETE"`, `"GET"`, `"HEAD"`, `"LINK"`, `"LOCK"`, `"MERGE"`, `"MKCOL"`, `"MKWORKSPACE"`, `"MOVE"`, `"NOTIFY"`, `"OPTIONS"`, `"PATCH"`, `"POLL"`, `"POST"`, `"PROPFIND"`, `"PROPPATCH"`, `"PUT"`, `"REPORT"`, `"RPC_IN_DATA"`, `"RPC_OUT_DATA"`, `"SEARCH"`, `"SUBSCRIBE"`, `"TRACE"`, `"TRACK"`, `"UNLINK"`, `"UNLOCK"`, `"UNSUBSCRIBE"`, `"VERSION_CONTROL"`, `"X-MS-ENUMATTS"`, `"*"`. |
| `policy.urls[].positionalParameters[].parameter.url.name` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.url.protocol` | `string` | Allowed values: `"http"`, `"https"`. |
| `policy.urls[].positionalParameters[].parameter.url.type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.urls[].positionalParameters[].parameter.valueMetacharOverrides` | `array` | List of configuration values. |
| `policy.urls[].positionalParameters[].parameter.valueMetacharOverrides[].isAllowed` | `boolean` | Enable or disable this feature. |
| `policy.urls[].positionalParameters[].parameter.valueMetacharOverrides[].metachar` | `string` | String configuration value. |
| `policy.urls[].positionalParameters[].parameter.valueType` | `string` | Allowed values: `"array"`, `"auto-detect"`, `"dynamic-content"`, `"dynamic-parameter-name"`, `"ignore"`, `"json"`, `"object"`, `"openapi-array"`, `"static-content"`, `"user-input"`, `"xml"`. |
| `policy.urls[].positionalParameters[].parameter.wildcardOrder` | `integer` | Numeric configuration value. |
| `policy.urls[].positionalParameters[].urlSegmentIndex` | `integer` | Numeric configuration value. |
| `policy.urls[].protocol` | `string` | Allowed values: `"http"`, `"https"`. |
| `policy.urls[].signatureOverrides` | `array` | List of configuration values. |
| `policy.urls[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.urls[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.urls[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.urls[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.urls[].type` | `string` | Allowed values: `"explicit"`, `"wildcard"`. |
| `policy.urls[].urlContentProfiles` | `array` | List of configuration values. |
| `policy.urls[].urlContentProfiles[].contentProfile` | `object` | Configuration object. |
| `policy.urls[].urlContentProfiles[].contentProfile.name` | `string` | String configuration value. |
| `policy.urls[].urlContentProfiles[].headerName` | `string` | String configuration value. |
| `policy.urls[].urlContentProfiles[].headerOrder` | `string\|integer` | Configuration field. |
| `policy.urls[].urlContentProfiles[].headerValue` | `string` | String configuration value. |
| `policy.urls[].urlContentProfiles[].name` | `string` | String configuration value. |
| `policy.urls[].urlContentProfiles[].type` | `string` | Allowed values: `"apply-content-signatures"`, `"apply-value-and-content-signatures"`, `"disallow"`, `"do-nothing"`, `"form-data"`, `"gwt"`, `"json"`, `"xml"`, `"grpc"`. |
| `policy.urls[].wildcardOrder` | `integer` | Numeric configuration value. |
| `policy.whitelist-ips` | `array` | List of configuration values. |
| `policy.whitelist-ips[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.whitelist-ips[].blockRequests` | `string` | Allowed values: `"always"`, `"never"`, `"policy-default"`. |
| `policy.whitelist-ips[].ipAddress` | `string` | String configuration value. |
| `policy.whitelist-ips[].ipMask` | `string` | String configuration value. |
| `policy.whitelist-ips[].neverLogRequests` | `boolean` | Enable or disable this feature. |
| `policy.whitelistIpReference` | `object` | Configuration object. |
| `policy.whitelistIpReference.link` | `string` | String configuration value. |
| `policy.xml-profiles` | `array` | List of configuration values. |
| `policy.xml-profiles[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.xml-profiles[].attackSignaturesCheck` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].defenseAttributes` | `object` | Configuration object. |
| `policy.xml-profiles[].defenseAttributes.allowCDATA` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].defenseAttributes.allowDTDs` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].defenseAttributes.allowExternalReferences` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].defenseAttributes.allowProcessingInstructions` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].defenseAttributes.maximumAttributeValueLength` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumAttributesPerElement` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumChildrenPerElement` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumDocumentDepth` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumDocumentSize` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumElements` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumNSDeclarations` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumNameLength` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.maximumNamespaceLength` | `string\|integer` | Configuration field. |
| `policy.xml-profiles[].defenseAttributes.tolerateCloseTagShorthand` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].defenseAttributes.tolerateLeadingWhiteSpace` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].defenseAttributes.tolerateNumericNames` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].description` | `string` | String configuration value. |
| `policy.xml-profiles[].enableWss` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].followSchemaLinks` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].name` | `string` | String configuration value. |
| `policy.xml-profiles[].signatureOverrides` | `array` | List of configuration values. |
| `policy.xml-profiles[].signatureOverrides[].enabled` | `boolean` | Enable or disable this feature. |
| `policy.xml-profiles[].signatureOverrides[].name` | `string` | String configuration value. |
| `policy.xml-profiles[].signatureOverrides[].signatureId` | `integer` | Numeric configuration value. |
| `policy.xml-profiles[].signatureOverrides[].tag` | `string` | String configuration value. |
| `policy.xml-profiles[].useXmlResponsePage` | `boolean` | Enable or disable this feature. |
| `policy.xml-validation-files` | `array` | List of configuration values. |
| `policy.xml-validation-files[].$action` | `string` | Allowed values: `"delete"`. |
| `policy.xml-validation-files[].contents` | `string` | String configuration value. |
| `policy.xml-validation-files[].fileName` | `string` | String configuration value. |
| `policy.xml-validation-files[].isBase64` | `boolean` | Enable or disable this feature. |
| `policy.xmlProfileReference` | `object` | Configuration object. |
| `policy.xmlProfileReference.link` | `string` | String configuration value. |
| `policy.xmlValidationFileReference` | `object` | Configuration object. |
| `policy.xmlValidationFileReference.link` | `string` | String configuration value. |
