use umineko_crypto_rsa::{RSAError, RSAHash, RSAPadding, RSAPrivateKey, RSAPublicKey, RSASignature, RSA};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

const PRIVATE: &str = "308204a20201000282010100defbcb2349e6daa2985e1e876065a821b62873ebd0dbc99e138e28a91b5fc0bdd1d6fea4a18be58ed9c53f26209c1fed191d036278d3a27aa0e778f998d184c90bea7175953b18546ef317f0de35101ccae40f2925ae4795fe866298e209a826023e3771a38015a0de88e7971108410a7e67cb5afa4331f8d66c81b211c1940294b7fb39e5ed32988f848aca56b58a878867eea3d3d001d1296dcfcb2f7b643a89d8c310cad95ed2be73c11c3c7480ceccdadc5d66977dcd11edc5960d90b3e2f2f29c02200954c15136639620c48d9460e6e062ef9fee9126fcd7fc0613c525024b5a522d782762eee7ea47a0e65cd6f3d2b2e0b525f4ce3fa36e330f2f4be3020301000102820100155d1c7652134b293eddeda0dccc8092524887eab50509c91a68895ec25fa730c89507aab04b9dffd4bf80305ff975599b095b94a8ace629479745d0ec224ecd9055b2ef28101461aa8ba1e492f594889dabc20418371d66b28f1f8d3442e69855a8ae5935e804aa7807b7e092622f1119514a7b79f4cc29e2295d37b959c99b53d790be4171a4b6386851b47bbae0276a9306571f182b705b448e7eef91cc82b91f8b9f645c8ce56c6e277d93b963cba26840b117389d7825ae78af9adc77713ac5e176871cef58a056c73ea3caad0a3d301b73487554950a59363fb45a985d84624a35c5279830771341e42386ae5b008d0cc3b70cfe8f63b0871cde18902102818100fcbd7f7869cca84a88f361c41c211ce4f495ba069a7530db88ce975ba17ee2d8d431f45ffd724bb81e8ee35e9a5627930f796bbf9a051a2771fb022b8e5ff654f4e860177bb1a45dda6d01c6c17af75b1e69487fe19a4c620b2ec579a2d5fba553544b617622e58b5f398f0d804821faa1244db45195b4b1f592c4a15a91811302818100e1dc0b6611adb927f0dade8b497cbec1d1a7085f31a31f37cf789ec01d783dd80a9b66e402db042ed5670cf6dde3d23d7c1203a9aabe79a1d3b3b7778fdcdccc28b8f7da7925b9dd8100edcccd5b15985e678d1116b8d1d47a579bd430ac5e78849caf9d9c3f105804f3040afab5648024da4ae2c3ac126e791e34d3804a33f102818036e0968af8bdfd54a1c3e6d8841b14810a32707ffa8db39c176a7426eb3bf7d988c987fc47b5c78724eb75a716efda0bee7238d91382441988802e0a73119714ff506d7cebd8b88dc05da6e31723b20dd0de9f65550101d0d008c9cc0d7554fca2c94cccceafe913880ba16a170e92822ef709003c2ebb5b60ad0b90d56f7e8d02818050bd5cc5cc24124098f56500ddf05e30e34596d490e6034eec37ee683720b8daf64fbf645b30f839d5c7d4f69b33ca0078cde7c94b64740ec9a3413ed88ad7d393eb2b8f4a27965dfcb3dc4e8e4ab55996c5e5c3ea1f7fc339490047c66e9806f5411df675d8857b31a9be143eb3818ddd9ebb8e7cec925a33a9fcb06ef817c102818050b72818ea4980bf8f3222585cb6ffabe9b91b245826187371277e0126ccfcea7f3f5ca84f07a1194efa60b8c22eb079cb0b17b6c93c8c54fb818d8342e4a914215ea189237be6edd2e219862cfb13ae6109dd7f4c26687f4287768deb0507eac8c38bbc20994d82b2d2a7ec8cbe4c27a8814f0c9d96477d04416fa87f109a11";
const PUBLIC: &str = "3082010a0282010100defbcb2349e6daa2985e1e876065a821b62873ebd0dbc99e138e28a91b5fc0bdd1d6fea4a18be58ed9c53f26209c1fed191d036278d3a27aa0e778f998d184c90bea7175953b18546ef317f0de35101ccae40f2925ae4795fe866298e209a826023e3771a38015a0de88e7971108410a7e67cb5afa4331f8d66c81b211c1940294b7fb39e5ed32988f848aca56b58a878867eea3d3d001d1296dcfcb2f7b643a89d8c310cad95ed2be73c11c3c7480ceccdadc5d66977dcd11edc5960d90b3e2f2f29c02200954c15136639620c48d9460e6e062ef9fee9126fcd7fc0613c525024b5a522d782762eee7ea47a0e65cd6f3d2b2e0b525f4ce3fa36e330f2f4be30203010001";
const DIGEST: &str = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";

fn message() -> Vec<u8> {
    (0..32).collect()
}

#[test]
fn keys() {
    let key = RSAPrivateKey::decode(&hex(PRIVATE)).unwrap();
    assert_eq!(key.bits(), 2048);
    assert_eq!(key.size(), 256);
    assert_eq!(key.public_key().encode(), hex(PUBLIC));
    assert_eq!(key.encode(), hex(PRIVATE));
    let public = RSAPublicKey::decode(&hex(PUBLIC)).unwrap();
    assert_eq!(public, key.public_key());
    assert_eq!(public.encode(), hex(PUBLIC));
    assert_eq!(RSAPrivateKey::decode(&hex(PUBLIC)).err(), Some(RSAError::Encoding));
    assert_eq!(RSAPublicKey::decode(&[0x30, 0x00]).err(), Some(RSAError::Encoding));
}

#[test]
fn foreign_ciphertexts() {
    let key = RSAPrivateKey::decode(&hex(PRIVATE)).unwrap();
    assert_eq!(key.decrypt(RSAPadding::OAEP(RSAHash::SHA256), &hex("b51cf5617d295ce45971e82813dc3ecef8cef4e6bed8c44738b0b9490a1155e2c1d8060799dd3ffe7d2d8428e94e54265d65d4e03a67af2426c8b91a0e47c45e0b6383c91b58a2fd1ef7b289c8f8c100fb3323d8edf06383180592a1e80422b55006d4f7a309379a6a137df234551a1d9c4f9dbae771803d486e046943ffb63f4a9a8de3a751a655d22570e7a35811ed326e22c2ed0286b2bdd26768c3afa1c8962248472035b8b267fa4726624802b4663c7941bb49e41ad4fcffe3b5c1a13d05ad4b23d6598cdb3cc8ca7223dc770f3d3a86301719bbed3418003b6a880a9a18e798a66bf34c9a6f2c6ad683656deb54320d7f00e6ed45afe6a031b760b3f3"), &[]).unwrap(), message());
    assert_eq!(key.decrypt(RSAPadding::OAEP(RSAHash::SHA1), &hex("13f3d7fa4a7f41d619d29e6a687685e72837b5db20df216138d4dd72814bea637f1100201b718317f21fb314fa594ce62c92d9d2d42ff0df6ff5a2b1ba2cad8cafa815aeaba307487445bacc014adc15665dbfbccb6ed977d65f35b08c53b46ba2870bc7948c9b7ef4370cae66730c69a9f88d9312be2f92ca6bfbeb056b16643837af558a0836ff7ce84d8afc8d1afb5b3b33d43b4286f799d590a837ee6d34ec1f4f03d3d3cbc59369afb1017784bd9425ce237cab7f3398e3219d133dad67a4a4ce601fdab2504930969455d72238b1adf36e795dbe6688d0c099858a8cae19389d1ff3e9975bc78d0b28665477df3a7ee492d11d1e7765958c29bb341867"), &[]).unwrap(), message());
    assert_eq!(key.decrypt(RSAPadding::PKCS1V15(RSAHash::SHA256), &hex("2af149eacdd0e47a04d938a31e39402238f3bb09938ed79c55256716f9dc4dccdbdb2e69af14ffc79fbff97f5b79c6cf9ffba196e1d8be40717f7528181add5e730b2b2bf564dbdfc62e6180d85dacfdf1a76546b512af5470aab88bdf4a1d3914dfaf2edbb09e8930c9626890c052aa0d1ded3340f700a15e17b28dbc03c8ead39870ce7e5056587db8f3ca90f7fd192138360ce109df7b509ad8c104e6c267b55e3b765dab3b62c303c1dfc30bcaf9f0af6c475b5c6ac94ee86c483841dbbfb89339554d68f10f649dbb14ae02c68f258dec33f6d9573d44b0290485abc9bea7e0f01aa74c2d1e6dd89c6196867eb8c65bb049d0bdc16e92e3bb1ef533fde8"), &[]).unwrap(), message());
}

#[test]
fn foreign_signatures() {
    let public = RSAPublicKey::decode(&hex(PUBLIC)).unwrap();
    let signature = RSASignature::decode(&hex("a61742ff86c3556aa360c9fea4d3ce44c4feaaf7737f500598fed725b4beb687b0cd525d24ed4b90234366c53b0f3352047cddc5827444815620dd639c27e1ccd0db56fa64a79e4ff85cdb1fc140a4364cbcf0ca242e40b44503f125e4b0e42c104c7da8897bc6f2ee05cfad771acd7b654179f8b611b78afa4a7391ec95031f6d3d3034715301394b4d06a96135f252fc345d19abce64e4b7dfc68fd3650571bdd0c821345a63d08d4ca0844e43e91b8c8a64c2787fdafbe1ccc0677da3287fef38d96056f796a000674953c7f646ae3d268354150ebbdadc2ef3f69ab059764a6a63d7312aaeb0b444bf134daed2a0847f1f85b2ba2b6207df1feebc95e8c7")).unwrap();
    assert_eq!(public.verify(RSAPadding::PKCS1V15(RSAHash::SHA256), &hex(DIGEST), &signature), Ok(()));
    let signature = RSASignature::decode(&hex("693d3be14b05de2216b9bb54a9c063b92d77925361d4e0cdad01f93af8ab56d87f093835d7553a3f9a8678f1037c373038e2a6db2553b460cce3df859e2591d57a2948ffe34e7b3f183acafa62283ff723e4d3c5b48968f5a7578a8373b24871a4e541382a7fc8c880088cfc24e3f1bc8c131c7a06035ff945af8f89548cb731cb777184baab9b4c9ff9a2a987d595095d585082897d88b6d9dd550b693d0b31347c83a7a8b3f691d753ffe39ae4e4bcd1c5a07949a35b4a403124023a218672df74ba87ce787bab37e86d260893cb4ac2c1961075a10edd654c248df972f2e319a9727726c52a478464b7f3eaa92342922f505a786fcfbd3c402d1ca86c63a1")).unwrap();
    assert_eq!(public.verify(RSAPadding::PSS(RSAHash::SHA256), &hex(DIGEST), &signature), Ok(()));
    let mut broken = hex(DIGEST);
    broken[0] ^= 1;
    assert_eq!(public.verify(RSAPadding::PSS(RSAHash::SHA256), &broken, &signature), Err(RSAError::Verification));
}

#[test]
fn foreign_acceptance() {
    let key = RSAPrivateKey::decode(&hex(PRIVATE)).unwrap();
    let message = message();
    let digest = RSAHash::SHA256.digest(&message);
    assert_eq!(key.public_key().encrypt(RSAPadding::OAEP(RSAHash::SHA256), &message, &[], &[9; 64]).unwrap(), hex("3840767a01bcb7271cd7a1f46b01dd0ed60bf68328e0453d6c1e22a041169ccebc8cf7db2680f4072ca58ebeb6a2c288c89ac344851ebbf9c4a3d3553ea353de193cdc992aabf37c58695697b4fded27839754e5e6a327c20698bebcda1db11c7822047794d30cf61e4536266987b0c645baa314b9cc21cdee561ba09aa7f8be8f01e15af6678298c8704809258553928b95aad07eabbb9a6e65ccf905c952d6ba83ddc8e6d619acf9803af37a2401aeb9e1df48110c7e4531830f77f458e2ed0e2d77e97145e59eb6c2bda4314fdd9ad70810f3160b2bb81911676de2b9f8c41f854dfbd0be66c5d07bcde16f486de7292317f05c999a0139c417d2528bd5a1"));
    assert_eq!(key.public_key().encrypt(RSAPadding::PKCS1V15(RSAHash::SHA256), &message, &[], &[9; 64]).unwrap(), hex("633a66f13886a7810073fe92e4b729204c970bc5b0cdcc6fccc5f8e52fa6e4faffd2956bc8600306869a37ffeed4cd67b61492b3c22032e49a9522e550d3ed791c842688efed8ab7798e5760867f799c2842c981bd6ddf866aacc2f0b00c37dae079f73fcb2cb65e45d27ae85a95621b1e0627d79cef716ebb567c23b90b525ca60eb016303386779e29cbb9c1a09233a0508a3fee927f955d359318814702073fe8710d288b4abaef5c6550507323285a49638f191f9f4f66dbae25e8eda20f14e93bd58fd9fcc5c78911a296f0221d638263ac53b0f71b94a42713f558d12e2a8bf9b430bb02ccb03c55814c4056d4f943d38c17779ba3824d6a1a1a7e38b1"));
    assert_eq!(key.sign(RSAPadding::PSS(RSAHash::SHA256), &digest, &[4; 32]).unwrap().encode(), hex("622601c94b695381edf46d27cfbdaa3c85264adb7c2523271c4a6f5a9df012db9c76cbb94bec3cd2adcd52e105df4ca201bfa158f7858a795122859c5304ed0232d0ffbb2e6c83f4ba4159afcac3eedbcd344d836eab48bd57f6cbf7ec120f823bb6d8080a59e153ad1dff0157497426e09f1e115682486b1b51d2845c53a1d5bceeb7ed2aedaf68649b8a2873e8a8bee905cc818297415f2eb86ced32fd9ffefe10a7b60a97d48fbe4c24e935a419b20f921aa39183c616948c59719987357315c3c21c6c10e5c49c9a00d0b713374ded63e5155e825a7312ed6af3f6f9aff9f335b46b7850517da12d072e6e015c1fc6018766a1fbb843a2b678555f9c7b31"));
    assert_eq!(key.sign(RSAPadding::PKCS1V15(RSAHash::SHA256), &digest, &[]).unwrap().encode(), hex("a61742ff86c3556aa360c9fea4d3ce44c4feaaf7737f500598fed725b4beb687b0cd525d24ed4b90234366c53b0f3352047cddc5827444815620dd639c27e1ccd0db56fa64a79e4ff85cdb1fc140a4364cbcf0ca242e40b44503f125e4b0e42c104c7da8897bc6f2ee05cfad771acd7b654179f8b611b78afa4a7391ec95031f6d3d3034715301394b4d06a96135f252fc345d19abce64e4b7dfc68fd3650571bdd0c821345a63d08d4ca0844e43e91b8c8a64c2787fdafbe1ccc0677da3287fef38d96056f796a000674953c7f646ae3d268354150ebbdadc2ef3f69ab059764a6a63d7312aaeb0b444bf134daed2a0847f1f85b2ba2b6207df1feebc95e8c7"));
}

#[test]
fn round_trip() {
    let key = RSAPrivateKey::decode(&hex(PRIVATE)).unwrap();
    let public = key.public_key();
    for hash in RSAHash::ALL {
        for padding in [RSAPadding::PKCS1V15(hash), RSAPadding::OAEP(hash)] {
            let room = padding.maximum_length(public.size()).unwrap();
            for length in [0, 1, 32, room] {
                let plaintext: Vec<u8> = (0..length).map(|index| index as u8).collect();
                let ciphertext = public.encrypt(padding, &plaintext, b"label", &[7; 64]).unwrap();
                assert_eq!(ciphertext.len(), public.size(), "{padding} {length}");
                assert_eq!(key.decrypt(padding, &ciphertext, b"label").unwrap(), plaintext, "{padding} {length}");
            }
            let long: Vec<u8> = (0..room + 1).map(|index| index as u8).collect();
            assert_eq!(public.encrypt(padding, &long, b"label", &[7; 64]).err(), Some(RSAError::Length), "{padding}");
        }
        let digest = hash.digest(&message());
        for padding in [RSAPadding::PKCS1V15(hash), RSAPadding::PSS(hash)] {
            let signature = key.sign(padding, &digest, &[3; 32]).unwrap();
            assert_eq!(signature.encode().len(), key.size(), "{padding}");
            assert_eq!(public.verify(padding, &digest, &signature), Ok(()), "{padding}");
            let mut broken = digest.clone();
            broken[0] ^= 1;
            assert_eq!(public.verify(padding, &broken, &signature), Err(RSAError::Verification), "{padding}");
        }
    }
}

#[test]
fn label_binding() {
    let key = RSAPrivateKey::decode(&hex(PRIVATE)).unwrap();
    let padding = RSAPadding::OAEP(RSAHash::SHA256);
    let ciphertext = key.public_key().encrypt(padding, &message(), b"first", &[9; 64]).unwrap();
    assert_eq!(key.decrypt(padding, &ciphertext, b"second").err(), Some(RSAError::Padding));
    assert_eq!(key.decrypt(padding, &ciphertext[..255], b"first").err(), Some(RSAError::Length));
}

#[test]
fn padding_pairs() {
    assert_eq!(RSAPadding::PSS(RSAHash::SHA256).cipher_name(), None);
    assert_eq!(RSAPadding::OAEP(RSAHash::SHA256).signature_name(), None);
    assert!(RSAPadding::PKCS1V15(RSAHash::SHA256).encryption());
    assert!(RSAPadding::PKCS1V15(RSAHash::SHA256).signature());
    let key = RSAPrivateKey::decode(&hex(PRIVATE)).unwrap();
    assert_eq!(key.sign(RSAPadding::OAEP(RSAHash::SHA256), &hex(DIGEST), &[]).err(), Some(RSAError::Padding));
    assert_eq!(key.decrypt(RSAPadding::PSS(RSAHash::SHA256), &[0; 256], &[]).err(), Some(RSAError::Padding));
}

#[test]
fn generation() {
    let parameters = RSA { bits: 2048, exponent: 65537 };
    let (private, public) = parameters.generate(b"a deterministic seed").unwrap();
    assert_eq!(private.bits(), 2048);
    assert_eq!(public.bits(), 2048);
    assert_eq!(private.public_key(), public);
    assert_eq!(RSAPrivateKey::decode(&private.encode()).unwrap(), private);
    let digest = RSAHash::SHA256.digest(&message());
    let signature = private.sign(RSAPadding::PSS(RSAHash::SHA256), &digest, &[5; 32]).unwrap();
    assert_eq!(public.verify(RSAPadding::PSS(RSAHash::SHA256), &digest, &signature), Ok(()));
    let ciphertext = public.encrypt(RSAPadding::OAEP(RSAHash::SHA256), &message(), &[], &[1; 64]).unwrap();
    assert_eq!(private.decrypt(RSAPadding::OAEP(RSAHash::SHA256), &ciphertext, &[]).unwrap(), message());
    assert_eq!(RSA { bits: 1024, exponent: 65537 }.generate(b"seed").err(), Some(RSAError::Size));
    assert_eq!(RSA { bits: 2048, exponent: 4 }.generate(b"seed").err(), Some(RSAError::Key));
    assert_eq!(RSA { bits: 2048, exponent: 65537 }.generate(b"").err(), Some(RSAError::Seed));
}
