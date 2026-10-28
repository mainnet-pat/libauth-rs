//! Port of `crypto/sha1.spec.ts`.

#[path = "hash.spec.helper.rs"]
mod hash_spec_helper;

use hash_spec_helper::TestHashFunction;
use libauth::{get_embedded_sha1_binary, instantiate_sha1, instantiate_sha1_bytes};

#[rustfmt::skip]
const ABC_HASH: [u8; 20] = [169, 153, 62, 54, 71, 6, 129, 106, 186, 62, 37, 113, 120, 80, 194, 108, 156, 208, 216, 157];

#[rustfmt::skip]
const TEST_HASH: [u8; 20] = [169, 74, 143, 229, 204, 177, 155, 166, 28, 76, 8, 115, 211, 145, 233, 135, 152, 47, 187, 211];

#[rustfmt::skip]
const LIBAUTH_HASH: [u8; 20] = [0, 53, 165, 162, 96, 82, 50, 137, 170, 76, 156, 212, 51, 123, 185, 71, 205, 18, 93, 14];

/// Substitution for Node.js's `createHash('sha1')`: the digests it produces
/// for the 100 fixed messages of `FixedInputs::new(NODE_JS_SEED)` (see
/// `hash.spec.helper.rs`), computed in Node.js.
const NODE_JS_DIGESTS: [&str; 100] = [
    "d4b79da3f67c1e8d78d650f55c5a3a78f3640fee",
    "6c5e70bb2aedff47edb6995f9625dd40fbdf1a0f",
    "fc489673d3cf1185d3c50cf4b26bc15c5b408323",
    "114b01a4ffd4791023a8e4f452c921aa37385ecd",
    "df0d563cbc22c259a210f0ff9519b8dfe17b507d",
    "052b22b4e65baa161b21c5f0539c35cf10f39399",
    "17f04f748c7063b35c474f9a2eafdf003bcfe8fc",
    "3aac5a8fe183a5b149c0a5d5247e68eb9e42a950",
    "0c8e42d5c4316d406bb7c362099606d0608c7b64",
    "859c053a96d6853780198ba9f121aff76e4178e1",
    "1e9e2544dda82778262604d8ba2fd3bb05e05b3d",
    "cd9853ec2e454a0355b44ab8dc8a7f2c666b2045",
    "5f484f5ba634fab431f583f4f42186892f249809",
    "d1fec2ac452cece575b8968201f7e2566744fc69",
    "c92daec0f2269e4b15ded2e80660c44103c12716",
    "d3bf6c1484137fef62d72e6d7a962d42e4f29799",
    "0642a9d6d1e26a5be09b26c7fb60dfe349a6bd3c",
    "c7e026e0b5f0c7c58b67deceba74b572072e11d0",
    "f8ec33996fc1f293c51d470396d8eace9c2ae91d",
    "90abd1b77ad1ba0b1bcc3de7f429b692bdd29976",
    "daac7dc0a099c494790cd7ab53c910cb0c7bf57a",
    "2515a346409b02e6a4e36b45e7d8040407258638",
    "2e5ceb114beca7b55da3de43c5ce36467c459aaa",
    "f739b6d3e9132eb836f9355f50a68e5329c18952",
    "90fb3dd62d1b92479a66d6980a705b186baf357f",
    "1d58287c01ee05785c942f876457f1aea47a5fa7",
    "e186700aa2d039f65c65efe9a229f62106736670",
    "aa9f25847a77e292e42c21413e8de5f9b49256c1",
    "7cfcec6fe4c605d9c4b23ade861d378c436cfb14",
    "d7138c3b4bbbe1914e262c47ba9785f40685ad7c",
    "5bea005b9cd445f15dd1b88c1a665f5288f53b6d",
    "cdf207f51239e1c3d5d2aed6b1af2f8c8aca1adb",
    "0cc66be5f28149ab71dcc3f4b09c58ac2b5ae2c9",
    "204bc58d689579fdf7f4a953846002b6de5c34e0",
    "a9ee02f6dcb57ecb12220e31ec6fb3b2c85328cc",
    "c4eea7ce49358d281a298e8debd73df0a2ac77cd",
    "01801778233a55b15db98c0c9a866403e801561a",
    "49b1b6562c3b4c94e0700427a7c3d1452385dea9",
    "6f1c7a02089e46de860cc3dd126ddf4234f2986a",
    "409024fcb1df4fd58f55de3179cbb313328b467d",
    "d5aa904eb9394607a363fd7348576617025abc36",
    "9b52745cf995c71e9d1b235865bb9706e2b9686a",
    "a5be49bd36fad7fa0110eebdc2ddf61f6b3530de",
    "da9b64d31d25955a96c920e9b7cafe6394608fbd",
    "fa25150b3c7015821904059e6691c1d1b53165cf",
    "f4226fd9b030240e66c7d78de9acc2402da7e206",
    "4b7995d9ce10477a6d6d970193ed0803368faf45",
    "f01aa68d41bbb9d409f6012a62c0a3b77cfe300d",
    "9392cd363769cbe0874855804aba9188a31ae050",
    "e02c3604add24df93f9a1626b110a6778a2cfb22",
    "1f45b73f01d93e37fb1cf778d49885fb948a31ee",
    "0fcd4c647c76301cf6498fd5c1dcfab387eecd71",
    "9bd7cee58f8702d62eba42ea2ad34af58879190d",
    "c6cf5951899b0be7fe69e3404aa54873b5c291be",
    "0abf549e0920e474d2d341b64872854bac01122b",
    "236b2b0f436fb7f4e6b1c6a9b490d9b2b0b811b8",
    "0232f6e5b73b9a1a6db39cfbd5de73affc703c56",
    "f8eb0110a33da827f7a5d43326aed22bb867db96",
    "afb76aa9f6e8e3d68685cc3a71ea8aacf2eac354",
    "e0a407b2ce21a031fa08ecfb2fa7f9a41170609e",
    "92f372334303408de20bca2321e1d4665b04507b",
    "d1eab7b6ad8ba9fe180098a5b3471eb6ae18ddea",
    "bdce2c4a6603e85c0ab5b958559df1ddabcd26bb",
    "cba2ccced6bf3c9798109396addb20c8f4c7b152",
    "7ca07af5a7ff4208e24ab8f0db309fcb728c57a4",
    "447766b07bb62ff4c58008fe7c44adc877508490",
    "6200010b11f859969505dc6d09a2a023570978e5",
    "2134b61993c1f1210c23b91da132b66514b394f2",
    "c993aa3e53252fd6ec2c9784e640a0ce2539cb17",
    "724b1329a8c3cf3f334f4349eac907d809e3a8e2",
    "00f27a10c24e3a837096eaa2d3550702679d24c2",
    "44414453e57e80a220ccfd0e2cd897f4df44d5a0",
    "888482f775e201b7002c271cff0b953e71902e8c",
    "3266c9791099405ddf305219c52f97b2b2087aa2",
    "c2bd198757253b927e8de202a770c996ff6fd2f1",
    "551eb99731db78afb7cb74e70423f7832e365105",
    "1fcbdd95e60f488f255d979692d0d33d0d018d82",
    "03018b4131bf638520e3ef8c3cf057e261092979",
    "8970da6da1af5c0aeeb9980be68ac633e0d8479c",
    "c479b5a63a9e45b1188c0aba1e55773fcba7c923",
    "35e7fcfad81d0d8bcaf21513555b58adee15cfe9",
    "af7c5f8cb8be0d5fc9ffa2a05817bf2d9f3a04ea",
    "e180b021ca63a688b2c14f84052b911e74eba247",
    "b06110d4116e182ef9d3b87e441024fcf388fc58",
    "f0a3e4e9871dce6793c4cfb7cfd77bd0721fee33",
    "05e71dcf87a3e8182d1aacd9fec9a7d1c7e15f68",
    "7d78ed96b6c5ee67a7d22e5465948f83c72d6458",
    "9bd2ba3641962ccdceec5218db52ee2af46aae3c",
    "3e4e82b605b5093b8556a90d2649cf9d805f10c3",
    "5bd28f3cc62fae71fe2101df85e977cf6b90a3ca",
    "e317cab2293ac74e7022f5577336a10fc3f49db0",
    "0cf1e05a30ca60f7a105abcf8c412be6890db715",
    "bb11e4b5e108701489fc10c6d1bb94d3e024dde8",
    "129f29eae04af27bb4611b1a4b9753e35b3fc7b6",
    "3f05044fe41acdb565f383932ce685efbf481c48",
    "03bcc4132472e4ae55199fe790a7ed2794248824",
    "a94500f6d8a745227fbb1a5a498f26e5c89e6e4c",
    "c3e125cebf337cafb431913995e387c20ecbc1cc",
    "5d8a1676a68da81303fbe65ceaa432e51ca2c9af",
    "6a027e22103e58636b45cb2c3c6d70631c04b4a6",
];

/// Substitution for `hash.js` (`hashJs.sha1()`): the digests it produces for
/// the 100 fixed messages of `FixedInputs::new(HASH_JS_SEED)` (see
/// `hash.spec.helper.rs`), computed in Node.js.
const HASH_JS_DIGESTS: [&str; 100] = [
    "e4d502591a4164e5df1887368a09bf187d0bc0b6",
    "0531e6614be522fcfbb09af0c58b950a7b869fbf",
    "9c4fa73f1681ba9978557dae5589c2c34cd805dd",
    "0f05ea6b7f711aa2ff76e85e68c0a9577364d4ea",
    "c59495346d9dec95f373d059a6223bf8cdb8773c",
    "63351639fd31f4ad445fe47cfbd9238bab0244cc",
    "e45e30d7a8432c6ece76f88b58ec8d042dbb3dc1",
    "16c46147e8749255b97b5b4d4541bb10b0d4c54a",
    "56b895ceea8fc2766071eafee4c124e7c74e8ec3",
    "bb6a320fbe64d8358951dfec3919d657d330334e",
    "d5cdaa6dd99bcf234eaac89c6745d635ed70d360",
    "d40db19ff7c2b5f30c51ac90d62537d3f5886ea3",
    "bb7abd2ec908f9917ac3a770a4dc4afa9ad03e65",
    "2c5ea705355bd834921b835100b5cb695092e98e",
    "07d84ea4423ba848543eb345b8ffcd98fdd3ccf5",
    "3b7f4ea63993315bbdcf08f397f84891de8da63f",
    "e1dff4f8c3a1aaa038e5511b130965bbb60efacc",
    "c92de1577b1355e514140d7abc58231c6c5c15f6",
    "5cfabbe6498b4f26d7a72ce19c708b84d4711f0c",
    "cb7d4933159969ad09900467cada521c538024cd",
    "cca01b20b60bf44f5224956e9619089801eac2ef",
    "a20af3948d9f91db563c318824229ea227d9ca4b",
    "a79d03b367abb4e124e2b13c3db90b746378fd14",
    "8e47abf033d9195c405028969a79f95b9512889b",
    "0485920a72200fd5f12b5ef540dac654e7c20a42",
    "6b38f0b3ca14a975ae47fdfa001d234097053068",
    "330bc37b536cf6313eb262f64b1fe3eaae9f784c",
    "bd36db19ebc4b29a8a33dea25f219901d3a6c3a6",
    "32cf27f53a2a5949a80bdc4559e1eb89b344bb87",
    "f9357a09fe2163a21abc3e934dbe729e304d63c4",
    "e1ed02c15f980028d99909f6608c563a065a3f9e",
    "3565afaddbe69e21ef764c5927d2e791caf24517",
    "6151ba8d91c3a9ad1aadff89c6a6de0a0a017a6b",
    "b82422747966a23d5b4e017e4958ad4bb91c47be",
    "7dd14420fb802b765f754b8eb178bdf8423dc1e2",
    "3d04eca64664c332b2e64b17af1c3f685c8ecaf6",
    "41e678d75f3cce66330ba740e7da34a5a28252c5",
    "ffdf1eb7cc26ad2fd80a7eebd706d98a293eb2f5",
    "b6941c18fa928a6e748f06e88c338f634ddf331d",
    "f80e41043c4957f5df6f6b941d19c7abb2b399ac",
    "757cf1ffee948cc4aa215ddd467dda15b98a72d7",
    "eaf0cb5a6c163498793e4860db59d11cc10ba855",
    "2bd5490ea168f41336c3e37e14c8f3e8dd0014ae",
    "fa075e02375467ef23ea08796ca326c0e611d992",
    "6a973edfad709f0638f7d74b8badd43f8b30428e",
    "bcf19cc3e67cbbc88185b5c57c8b812224c938a3",
    "6bda6034116ca519b03d8acf832c912db5a3c6a9",
    "205433eca35e4ffd8d5258ef9eb2210c96fbee67",
    "637dd75aca39abb7bf5f37c00266570c66146a75",
    "a2dfb97ff2389d465256a90d19e5f3a22cd8e327",
    "639a48feaae63e88ba5b5f7464799b2b63882934",
    "1d7612a01135072a5339d87ff963fdbaaf58277f",
    "83c42cc1a49d6859805629ed27bf67e4b15dbc33",
    "f1465fb68512fdfd7428d0aae8863fe9f1485a86",
    "15bcf0a37a4bf6c8d938e8b083dd6f073fcc9506",
    "8c6581bdf53e3fcea13150c2cda26d66c27f2b0c",
    "820e64411094b23b8c6623b231131bff17c44dbc",
    "e8b6aa2510c707e9d4d88a37d58f7052a0b28745",
    "2d4bc2d56f9191561774e31619ecfdb47b13b8ac",
    "abffc4bcff072e001e063098a30af742f95f6af8",
    "fe20ccb084c0c9b87fde677e47e24819b560517a",
    "193a3226a7a6ae8c8b888c5121f90bd9a1006fa6",
    "71af3b4113c06ee66219681e6254535cd5675e6c",
    "17dd7a90df40ad5ffdde98889f1adc6f5442c44d",
    "3d23775a1ea81d127153058359bcc72596d1ed5f",
    "cfd69ba704208512c445de69f161a12ca738725e",
    "91ee89238712cdd2070e98c2d8c947a6d240fed2",
    "181693d067388e29a176a99d3842eefc5e236ec9",
    "b8953cf0baca9e70db0de8deb339bb13abd49265",
    "01088c1d493c87d74e931b7c61268f9c399d5c5d",
    "c5d7ff42652cb53c1e9458f00021bc3987515b07",
    "600b1fabbed8e9bc4191953b5e899fd0ab9cb396",
    "b0dd65339c4fe028eb6aea52e80d4817cbcbdfb0",
    "a662df6a1adc2811dc2c40338edf156162b65bbd",
    "892aa90a2a1e313daf9294a4d0c73cefa15c6c10",
    "1becba4a78951428f31f4935c5da6296425790e2",
    "0abbd7015d840a717262d7a77a8d88561dc08d77",
    "51cf9d73597d7a9d664132e8ec4b58d9d0e03daa",
    "24ea7caf4fecbcc128d8b8db571ed075600a4e05",
    "877143c82a7c71f663d50681138cbe619d07c9ef",
    "11b71a2533b6667ddc428a1c7e94af779f734265",
    "436f18f5cad882841e74e588748b3ac4778e691a",
    "e569f4351b9b3b258a017ca6a90cfcf643766c64",
    "fc4e66aecb8f4570ae0a1014fbe8bdd50fe252bc",
    "fe1bc07f128aecf8883e417a6df96704bcafe160",
    "1de58a9246a554ad41dc174b212667cef63c92d9",
    "fe2cf807082fd4e970742cb8425ae1edf0a8ca08",
    "ba52de522b7361f0f1900b290ae7d9ad146d27b6",
    "60ac007bdb6a702b13be2e6ea1435c9ce4a56b98",
    "d389664c2daa1458636c2931d5f17c729476b5c6",
    "34c43fc4a1f95bb5100aa4765be2c91e307fab69",
    "dd7ca632fdd92e216c998ade1bd9b8c7bd240b5b",
    "6ba8a290dbd93ab63fec00665393ea209ea9efa5",
    "77c6d7c3b9b96fe51e7f31e43244012820b7d977",
    "df5b1e23831605cd9b8d43fc907039bd6ab4c64e",
    "5b1c063198fa9f1d370560777951b28c154e0e0e",
    "88eafae37dfd22724c74053e21d311c25325ddc9",
    "e7ef5ce76731346d3ca03edbb39963cec371eaf8",
    "73bc26659d9887068012361a653377062e21a1c3",
    "8691761247c47abf30fb31456d9febf099fc33aa",
];

/// `testHashFunction<Sha1>({ ... })`
const PARAMETERS: TestHashFunction = TestHashFunction {
    abc_hash: &ABC_HASH,
    get_embedded_binary: get_embedded_sha1_binary,
    hash_function_name: "sha1",
    instantiate: instantiate_sha1,
    instantiate_bytes: instantiate_sha1_bytes,
    libauth_hash: &LIBAUTH_HASH,
    node_js_algorithm: "sha1",
    node_js_digests: &NODE_JS_DIGESTS,
    hash_js_digests: &HASH_JS_DIGESTS,
    test_hash: &TEST_HASH,
};

#[test]
fn crypto_sha1_get_embedded_binary_returns_the_proper_binary() {
    hash_spec_helper::get_embedded_binary_returns_the_proper_binary(&PARAMETERS);
}

#[test]
fn crypto_sha1_instantiated_with_embedded_binary() {
    hash_spec_helper::instantiated_with_embedded_binary(&PARAMETERS);
}

#[test]
fn fast_check_crypto_sha1_instantiated_with_bytes() {
    hash_spec_helper::instantiated_with_bytes(&PARAMETERS);
}

#[test]
fn crypto_sha1_incremental_hashing() {
    hash_spec_helper::incremental_hashing(&PARAMETERS);
}
