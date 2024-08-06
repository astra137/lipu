import { assertEquals } from '$std/assert/mod.ts'
import { decodeBase64 } from '$std/encoding/base64.ts'
import { decodeBase64Url } from '$std/encoding/base64url.ts'
import { decodeHex } from '$std/encoding/hex.ts'
import * as AuthData from './authdata.ts'

const AUTHDATA_AT = decodeBase64(
	'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAJch83ZdWwUm4niTLNjZU81AAIHa7Ksm5br3hAh3UjxP9+4rqu8BEsD+7SZ2xWe1/yHv6pAEDAzkBACBZAQDcxA7Ehs9goWB2Hbl6e9v+aUub9rvy2M7Hkvf+iCzMGE63e3sCEW5Ru33KNy4um46s9jalcBHtZgtEnyeRoQvszis+ws5o4Da0vQfuzlpBmjWT1dV6LuP+vs9wrfObW4jlA5bKEIhv63+jAxOtdXGVzo75PxBlqxrmrr5IR9n8Fw7clwRsDkjgRHaNcQVbwq/qdNwU5H3hZKu9szTwBS5NGRq01EaDF2014YSTFjwtAmZ3PU1tcO/QD2U2zg6eB5grfWDeAJtRE8cbndDWc8aLL0aeC37Q36+TVsGe6AhBgHEw6eO3I3NW5r9v/26CqMPBDwmEundeq1iGyKfMloobIUMBAAE=',
)

const AUTHDATA_ED = decodeBase64(
	'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2OBAAAAjaFxZXhhbXBsZS5leHRlbnNpb254dlRoaXMgaXMgYW4gZXhhbXBsZSBleHRlbnNpb24hIElmIHlvdSByZWFkIHRoaXMgbWVzc2FnZSwgeW91IHByb2JhYmx5IHN1Y2Nlc3NmdWxseSBwYXNzaW5nIGNvbmZvcm1hbmNlIHRlc3RzLiBHb29kIGpvYiE=',
)

const AUTHDATA_AT_ED = decodeHex(
	'49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763c500000025c87cdd9756c149b89e24cb363654f350002076bb2ac9b96ebde1021dd48f13fdfb8aeabbc044b03fbb499db159ed7fc87bfaa401030339010020590100dcc40ec486cf60a160761db97a7bdbfe694b9bf6bbf2d8cec792f7fe882ccc184eb77b7b02116e51bb7dca372e2e9b8eacf636a57011ed660b449f2791a10becce2b3ec2ce68e036b4bd07eece5a419a3593d5d57a2ee3febecf70adf39b5b88e50396ca10886feb7fa30313ad757195ce8ef93f1065ab1ae6aebe4847d9fc170edc97046c0e48e044768d71055bc2afea74dc14e47de164abbdb334f0052e4d191ab4d44683176d35e18493163c2d0266773d4d6d70efd00f6536ce0e9e07982b7d60de009b5113c71b9dd0d673c68b2f469e0b7ed0dfaf9356c19ee80841807130e9e3b7237356e6bf6fff6e82a8c3c10f0984ba775eab5886c8a7cc968a1b2143010001A1716578616D706C652E657874656E73696F6E6576616C7565',
)

Deno.test('decode authData with credential', () => {
	assertEquals(AuthData.flags(AUTHDATA_AT), {
		up: true,
		uv: false,
		be: false,
		bs: false,
		at: true,
		ed: false,
	})
	assertEquals(AuthData.signCount(AUTHDATA_AT), 37)
	assertEquals(
		AuthData.aaguid(AUTHDATA_AT),
		decodeBase64Url('yHzdl1bBSbieJMs2NlTzUA'),
	)
	assertEquals(
		AuthData.credentialId(AUTHDATA_AT),
		decodeBase64Url('drsqybluveECHdSPE_37iuq7wESwP7tJnbFZ7X_Ie_o'),
	)
	assertEquals(AuthData.credentialAlg(AUTHDATA_AT), -257)
})

Deno.test('decode authData with extensions', () => {
	assertEquals(AuthData.flags(AUTHDATA_ED), {
		up: true,
		uv: false,
		be: false,
		bs: false,
		at: false,
		ed: true,
	})
	assertEquals(
		AuthData.extensions(AUTHDATA_ED)?.get('example.extension'),
		'This is an example extension! If you read this message, you probably successfully passing conformance tests. Good job!',
	)
})

Deno.test('decode authData with credential and extensions', () => {
	assertEquals(
		AuthData.rpIdHash(AUTHDATA_AT_ED),
		decodeHex(
			'49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763',
		),
	)
	assertEquals(AuthData.flags(AUTHDATA_AT_ED), {
		up: true,
		uv: true,
		be: false,
		bs: false,
		at: true,
		ed: true,
	})
	assertEquals(AuthData.credentialAlg(AUTHDATA_AT_ED), -257)
	assertEquals(
		AuthData.extensions(AUTHDATA_AT_ED)?.get('example.extension'),
		'value',
	)
})
