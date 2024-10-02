//! Crate for parsing SOME/IP payload.

#![deny(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

#[macro_use]
extern crate log;

pub mod fibex;
pub mod fibex2som;
pub mod som;

#[doc(hidden)]
mod som2text;

#[cfg(test)]
mod tests {
    use crate::fibex::{FibexParser, FibexReader};
    use crate::fibex2som::FibexTypes;
    use crate::som::SOMParser;
    use crate::som::SOMType;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    #[ignore]
    fn fibex_info() {
        let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/idcevo-hv-fibex.xml");
        let reader = FibexReader::from_file(file).unwrap();
        let model = FibexParser::try_parse(vec![reader]).expect("parse failed");

        println!("services: {}", model.services.len());
        assert_eq!(884, model.services.len());
        println!("types: {}", model.types.len());
        assert_eq!(17267, model.types.len());

        let mut types: HashMap<String, Box<dyn SOMType>> = HashMap::new();

        for service in &model.services {
            for method in &service.methods {
                if let Some(fibex_type) = &method.request {
                    if let Ok(som_type) = FibexTypes::build(fibex_type) {
                        types.insert(fibex_type.id.clone(), som_type);
                    }
                }
                if let Some(fibex_type) = &method.response {
                    if let Ok(som_type) = FibexTypes::build(fibex_type) {
                        types.insert(fibex_type.id.clone(), som_type);
                    }
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn parse_msg_518090() {
        /* Raw DLT-MSG

        DLT-Hdrs:
        444c 5401 b1a6 d465 5bff 0300 4944 4345
        3d89 0047 4944 4345 0000 023b 01b8 bc25
        1502 5653 4950 5443 0000

        Arg-0:
        0004 0000 0a00 : Type-Info
        0000 0000 0000 ff01 0001

        Arg-1:
        0004 0000 1700 : Type-Info
        3401 8002 : Service-Id, Methdo-ID
        0000 000f : Length
        0000 f59d : Client-ID, Session-ID
        0104 0200 : Proto, Version, MSG-Type, Ret-Code

        Payload:
        0000 0000 0000 00
         */

        // => Version in MSG: 4, Version in Fibex: 3 !!

        let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/idcevo-hv-fibex.xml");
        let reader = FibexReader::from_file(file).unwrap();
        let model = FibexParser::try_parse(vec![reader]).expect("parse failed");

        let service = model.get_service(13313, 3).unwrap();
        println!("service: {}", service.name); // StatusDisplayDriver
        let method = service.get_method(32770).unwrap();
        println!("method: {}", method.name); // dynamicDisplayDriverAssistance

        let fibex_type = method.get_request().unwrap();
        println!("request: {}", fibex_type.id);
        //println!("{:?}", fibex_type);

        /* Expected Payload:
            length  : commonCRCLength (UInt16)
            counter : commonCRCCounter (UInt16)
            dataID  : commonCRCID (UInt32)
            cRC     : commonCRC (UInt32)
            displaySpeed : Struct(Value:Float32, Unit:UInt8)
        */
        // => Payload in Msg is too short !!
        let payload = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut som_parser = SOMParser::new(&payload);
        let mut som_type = FibexTypes::build(fibex_type).expect("build");
        println!("before:\n{:?}", som_type);
        let result = som_type.parse(&mut som_parser);
        println!("after:\n{}", som_type);
        println!("=> {:?}", result);
    }

    #[test]
    fn parse_msg_595743() {
        let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/idcevo-hv-fibex.xml");
        let reader = FibexReader::from_file(file).unwrap();
        let model = FibexParser::try_parse(vec![reader]).expect("parse failed");

        let service = model.get_service(63841, 1).unwrap();
        println!("service: {}", service.name);
        let method = service.get_method(34077).unwrap();
        println!("method: {}", method.name);
        let fibex_type = method.get_request().unwrap();

        println!("request: {}", fibex_type.id);
        //println!("{:?}", fibex_type);

        let payload = [0x01, 0xfe, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut som_parser = SOMParser::new(&payload);
        let mut som_type = FibexTypes::build(fibex_type).expect("build");
        println!("before:\n{}", som_type);
        let result = som_type.parse(&mut som_parser);
        println!("after:\n{}", som_type);
        println!("=> {:?}", result);
        // Err(InvalidPayload("Invalid Enum value 254 at offset 1"))
    }

    #[test]
    #[ignore]
    fn parse_msg_821281() {
        let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/idcevo-hv-fibex.xml");
        let reader = FibexReader::from_file(file).unwrap();
        let model = FibexParser::try_parse(vec![reader]).expect("parse failed");

        let service = model.get_service(45087, 1).unwrap();
        println!("service: {}", service.name);
        let method = service.get_method(32769).unwrap();
        println!("method: {}", method.name);
        let fibex_type = method.get_request().unwrap();

        println!("request: {}", fibex_type.id);
        //println!("{:?}", fibex_type);

        let payload = [
            0x00, 0x33, 0x7b, 0x0a, 0x01, 0x00, 0x00, 0x1a, 0x61, 0x5a, 0x13, 0x0c, 0x00, 0x00,
            0x00, 0x15, 0x18, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0xd5, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x18, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01,
        ];
        let mut som_parser = SOMParser::new(&payload);
        let mut som_type = FibexTypes::build(fibex_type).expect("build");
        println!("before:\n{}", som_type);
        let result = som_type.parse(&mut som_parser);
        println!("after:\n{}", som_type);
        println!("=> {:?}", result);
    }

    #[test]
    #[ignore]
    fn parse_msg_crash() {
        let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/idcevo-hv-fibex.xml");
        let reader = FibexReader::from_file(file).unwrap();
        let model = FibexParser::try_parse(vec![reader]).expect("parse failed");

        let service = model.get_service(46434, 1).unwrap();
        println!("service: {}", service.name);
        let method = service.get_method(32769).unwrap();
        println!("method: {}", method.name);
        let fibex_type = method.get_request().unwrap();

        println!("request: {}", fibex_type.id);
        println!("{:#?}", fibex_type);

        let payload = [
            0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x3C, 0xEF, 0xBB, 0xBF, 0x41, 0x63, 0x63,
            0x6F, 0x75, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E,
            0x50, 0x72, 0x6F, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75,
            0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x2E,
            0x30, 0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x49, 0x64, 0x00, 0x00, 0x00,
            0x00, 0x51, 0x04, 0x00, 0x00, 0x00, 0x4C, 0xEF, 0xBB, 0xBF, 0x41, 0x63, 0x63, 0x6F,
            0x75, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x50,
            0x72, 0x6F, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75, 0x6E,
            0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x2E, 0x30,
            0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63,
            0x74, 0x69, 0x6F, 0x6E, 0x73, 0x2E, 0x30, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00,
        ];
        let mut som_parser = SOMParser::new(&payload);
        let mut som_type = FibexTypes::build(fibex_type).expect("build");
        println!("before:\n{}", som_type);
        let result = som_type.parse(&mut som_parser);
        println!("after:\n{}", som_type);
        println!("=> {:?}", result);
    }

    #[test]
    #[ignore]
    fn parse_broken_fibex() {
        use std::io::BufReader;
        use stringreader::StringReader;

        let xml = r#"
            <fx:SERVICE-INTERFACE xsi:type="service:SERVICE-INTERFACE-TYPE" ID="BMW_INFOTAINMENT_PERSONALIZATION_AccountProtectionProvider">
                <ho:SHORT-NAME>AccountProtectionProvider</ho:SHORT-NAME>
                <fx:SERVICE-IDENTIFIER>46434</fx:SERVICE-IDENTIFIER>
                <fx:PACKAGE-REF ID-REF="ID_P_BMW_1_INFOTAINMENT_1_PERSONALIZATION_1"/>
                <service:API-VERSION>
                    <service:MAJOR>1</service:MAJOR>
                    <service:MINOR>0</service:MINOR>
                </service:API-VERSION>
                <service:FIELDS>
                <service:FIELD ID="BMW_INFOTAINMENT_PERSONALIZATION_AccountProtectionProvider_accountProtections">
                    <ho:SHORT-NAME>accountProtections</ho:SHORT-NAME>
                    <fx:DATATYPE-REF ID-REF="BMW_INFOTAINMENT_PERSONALIZATION_AccountProtection"/>
                    <fx:ARRAY-DECLARATION>
                    <fx:ARRAY-DIMENSION>
                        <fx:DIMENSION>1</fx:DIMENSION>
                        <fx:MAXIMUM-SIZE>10000</fx:MAXIMUM-SIZE>
                    </fx:ARRAY-DIMENSION>
                    </fx:ARRAY-DECLARATION>
                    <fx:UTILIZATION>
                    <fx:SERIALIZATION-ATTRIBUTES>
                        <fx:ARRAY-LENGTH-FIELD-SIZE>32</fx:ARRAY-LENGTH-FIELD-SIZE>
                    </fx:SERIALIZATION-ATTRIBUTES>
                    </fx:UTILIZATION>
                    <service:ACCESS-PERMISSION>NOTIFY_ONLY</service:ACCESS-PERMISSION>
                    <service:NOTIFIER>
                        <service:NOTIFICATION-IDENTIFIER>32769</service:NOTIFICATION-IDENTIFIER>
                    </service:NOTIFIER>
                </service:FIELD>
                </service:FIELDS>
            </fx:SERVICE-INTERFACE>

            <fx:DATATYPE xsi:type="fx:COMPLEX-DATATYPE-TYPE" ID="BMW_INFOTAINMENT_PERSONALIZATION_AccountProtection">
                <ho:SHORT-NAME>AccountProtection</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_BMW_1_INFOTAINMENT_1_PERSONALIZATION_1"/>
                <fx:COMPLEX-DATATYPE-CLASS>STRUCTURE</fx:COMPLEX-DATATYPE-CLASS>
                <fx:MEMBERS>
                    <fx:MEMBER ID="BMW_INFOTAINMENT_PERSONALIZATION_AccountProtection_accountId">
                        <ho:SHORT-NAME>accountId</ho:SHORT-NAME>
                        <ho:DESC>Id of the account to unlink the access key.</ho:DESC>
                        <fx:DATATYPE-REF ID-REF="CURRENT_PROJECT_STRING_UTF8_DYNAMIC"/>
                        <fx:POSITION>0</fx:POSITION>
                    </fx:MEMBER>
                    <fx:MEMBER ID="BMW_INFOTAINMENT_PERSONALIZATION_AccountProtection_accountProtections">
                        <ho:SHORT-NAME>accountProtections</ho:SHORT-NAME>
                        <fx:DATATYPE-REF ID-REF="BMW_INFOTAINMENT_PERSONALIZATION_Protection"/>
                        <fx:ARRAY-DECLARATION>
                        <fx:ARRAY-DIMENSION>
                            <fx:DIMENSION>1</fx:DIMENSION>
                            <fx:MAXIMUM-SIZE>10000</fx:MAXIMUM-SIZE>
                        </fx:ARRAY-DIMENSION>
                        </fx:ARRAY-DECLARATION>
                        <fx:UTILIZATION>
                        <fx:SERIALIZATION-ATTRIBUTES>
                            <fx:ARRAY-LENGTH-FIELD-SIZE>32</fx:ARRAY-LENGTH-FIELD-SIZE>
                        </fx:SERIALIZATION-ATTRIBUTES>
                        </fx:UTILIZATION>
                        <fx:POSITION>1</fx:POSITION>
                    </fx:MEMBER>
                </fx:MEMBERS>
            </fx:DATATYPE>
   
            <fx:DATATYPE xsi:type="fx:COMPLEX-DATATYPE-TYPE" ID="BMW_INFOTAINMENT_PERSONALIZATION_Protection">
                <ho:SHORT-NAME>Protection</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_BMW_1_INFOTAINMENT_1_PERSONALIZATION_1"/>
                <fx:COMPLEX-DATATYPE-CLASS>STRUCTURE</fx:COMPLEX-DATATYPE-CLASS>
                <fx:MEMBERS>
                <fx:MEMBER ID="BMW_INFOTAINMENT_PERSONALIZATION_Protection_type">
                    <ho:SHORT-NAME>type</ho:SHORT-NAME>
                    <ho:DESC>Protection type.</ho:DESC>
                    <fx:DATATYPE-REF ID-REF="CURRENT_PROJECT_UInt16"/>
                    <fx:POSITION>0</fx:POSITION>
                </fx:MEMBER>
                <fx:MEMBER ID="BMW_INFOTAINMENT_PERSONALIZATION_Protection_data">
                    <ho:SHORT-NAME>data</ho:SHORT-NAME>
                    <ho:DESC>Protection data</ho:DESC>
                    <fx:DATATYPE-REF ID-REF="CURRENT_PROJECT_STRING_UTF8_DYNAMIC"/>
                    <fx:POSITION>1</fx:POSITION>
                </fx:MEMBER>
                </fx:MEMBERS>
            </fx:DATATYPE>

            <fx:DATATYPE xsi:type="fx:COMMON-DATATYPE-TYPE" ID="CURRENT_PROJECT_UInt16">
                <ho:SHORT-NAME>UInt16</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_BMW_1"/>
                <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt16_coding"/>
            </fx:DATATYPE>

            <fx:DATATYPE xsi:type="fx:COMMON-DATATYPE-TYPE" ID="CURRENT_PROJECT_STRING_UTF8_DYNAMIC">
                <ho:SHORT-NAME>STRING_UTF8_DYNAMIC</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_BMW_1"/>
                <fx:CODING-REF ID-REF="CURRENT_PROJECT_STRING_UTF8_DYNAMIC_coding"/>
            </fx:DATATYPE>

            <fx:PROCESSING-INFORMATION>
                <fx:CODINGS>
                        <fx:CODING ID="CURRENT_PROJECT_STRING_UTF8_DYNAMIC_coding">
                            <ho:SHORT-NAME>CODING_STRING_UTF8_DYNAMIC</ho:SHORT-NAME>
                            <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UNICODE2STRING" CATEGORY="LEADING-LENGTH-INFO-TYPE" ENCODING="UTF-8" TERMINATION="ZERO">
                                <ho:MIN-LENGTH>8</ho:MIN-LENGTH>
                                <ho:MAX-LENGTH>256</ho:MAX-LENGTH>
                            </ho:CODED-TYPE>
                        </fx:CODING>

                        <fx:CODING ID="CURRENT_PROJECT_UInt16_coding">
                            <ho:SHORT-NAME>CODING_UInt16</ho:SHORT-NAME>
                            <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UINT16" CATEGORY="STANDARD-LENGTH-TYPE"/>
                        </fx:CODING>
                </fx:CODINGS>
            </fx:PROCESSING-INFORMATION>
        "#;

        let reader = FibexReader::from_reader(BufReader::new(StringReader::new(xml))).unwrap();
        let model = FibexParser::parse(vec![reader]).expect("parse failed");

        println!("types: {}", model.types.len());
        assert_eq!(5, model.types.len());
        assert_eq!(2, model.codings.len());

        let service = model.get_service(46434, 1).unwrap();
        println!("service: {}", service.name);
        let method = service.get_method(32769).unwrap();
        println!("method: {}", method.name);
        let fibex_type = method.get_request().unwrap();

        println!("request: {}", fibex_type.id);
        println!("{:#?}", fibex_type);

        let payload = [
            0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x3C, 0xEF, 0xBB, 0xBF, 0x41, 0x63, 0x63,
            0x6F, 0x75, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E,
            0x50, 0x72, 0x6F, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75,
            0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x2E,
            0x30, 0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x49, 0x64, 0x00, 0x00, 0x00,
            0x00, 0x51, 0x04, 0x00, 0x00, 0x00, 0x4C, 0xEF, 0xBB, 0xBF, 0x41, 0x63, 0x63, 0x6F,
            0x75, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x50,
            0x72, 0x6F, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75, 0x6E,
            0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x2E, 0x30,
            0x2E, 0x61, 0x63, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63,
            0x74, 0x69, 0x6F, 0x6E, 0x73, 0x2E, 0x30, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00,
        ];

        let mut som_parser = SOMParser::new(&payload);
        let mut som_type = FibexTypes::build(fibex_type).expect("build");

        println!("SOM-TYPE\n{:#?}\n", som_type);

        println!("before:\n{}", som_type);
        let result = som_type.parse(&mut som_parser);
        println!("after:\n{}", som_type);
        println!("=> {:?}", result);

        println!("SOM-TYPE\n{:#?}\n", som_type);
    }

    #[test]
    #[ignore]
    fn parse_bitmask_enum() {
        use std::io::BufReader;
        use stringreader::StringReader;

        let xml = r#"
            <fx:SERVICE-INTERFACE xsi:type="service:SERVICE-INTERFACE-TYPE" ID="bmw_software_idcevo_pdugateway_IDCevoGateway">
                <ho:SHORT-NAME>IDCevoGateway</ho:SHORT-NAME>
                <fx:SERVICE-IDENTIFIER>63841</fx:SERVICE-IDENTIFIER>
                <fx:PACKAGE-REF ID-REF="ID_P_bmw_1_software_1_idcevo_1_pdugateway_1"/>
                <service:API-VERSION>
                    <service:MAJOR>1</service:MAJOR>
                    <service:MINOR>0</service:MINOR>
                </service:API-VERSION>
                <service:FIELDS>
                    <service:FIELD ID="bmw_software_idcevo_pdugateway_IDCevoGateway_RotaryControllerVolume_RxPort">
                        <ho:SHORT-NAME>RotaryControllerVolume_RxPort</ho:SHORT-NAME>
                        <fx:DATATYPE-REF ID-REF="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerVolumePduWrapper"/>
                        <service:ACCESS-PERMISSION>NOTIFY_ONLY</service:ACCESS-PERMISSION>
                        <service:NOTIFIER>
                            <service:NOTIFICATION-IDENTIFIER>34077</service:NOTIFICATION-IDENTIFIER>
                        </service:NOTIFIER>
                    </service:FIELD>
                </service:FIELDS>
            </fx:SERVICE-INTERFACE>

            <fx:DATATYPE xsi:type="fx:COMPLEX-DATATYPE-TYPE" ID="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerVolumePduWrapper">
                <ho:SHORT-NAME>RotaryControllerVolumePduWrapper</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_bmw_1_software_1_idcevo_1_pdugateway_1_IDCevoTypes_1"/>
                <fx:COMPLEX-DATATYPE-CLASS>STRUCTURE</fx:COMPLEX-DATATYPE-CLASS>
                <fx:MEMBERS>
                <fx:MEMBER ID="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerVolumePduWrapper_RotaryControllerIncrement">
                    <ho:SHORT-NAME>RotaryControllerIncrement</ho:SHORT-NAME>
                    <fx:DATATYPE-REF ID-REF="CURRENT_PROJECT_UInt8"/>
                    <fx:UTILIZATION>
                        <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_invalidValue255_coding"/>
                        <fx:BIT-LENGTH>8</fx:BIT-LENGTH>
                        <fx:IS-HIGH-LOW-BYTE-ORDER>false</fx:IS-HIGH-LOW-BYTE-ORDER>
                    </fx:UTILIZATION>
                    <fx:POSITION>0</fx:POSITION>
                </fx:MEMBER>
                <fx:MEMBER ID="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerVolumePduWrapper_RotaryControllerDirection">
                    <ho:SHORT-NAME>RotaryControllerDirection</ho:SHORT-NAME>
                    <fx:DATATYPE-REF ID-REF="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerDirection"/>
                    <fx:UTILIZATION>
                        <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_2bit_invalidValue3_coding"/>
                        <fx:IS-HIGH-LOW-BYTE-ORDER>false</fx:IS-HIGH-LOW-BYTE-ORDER>
                    </fx:UTILIZATION>
                    <fx:POSITION>1</fx:POSITION>
                </fx:MEMBER>
                <fx:MEMBER ID="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerVolumePduWrapper_PaddingSignal1">
                    <ho:SHORT-NAME>PaddingSignal1</ho:SHORT-NAME>
                    <fx:DATATYPE-REF ID-REF="CURRENT_PROJECT_UInt8"/>
                    <fx:UTILIZATION>
                        <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_invalidValue63_coding"/>
                        <fx:BIT-LENGTH>6</fx:BIT-LENGTH>
                        <fx:IS-HIGH-LOW-BYTE-ORDER>false</fx:IS-HIGH-LOW-BYTE-ORDER>
                    </fx:UTILIZATION>
                    <fx:POSITION>2</fx:POSITION>
                </fx:MEMBER>
                <fx:MEMBER ID="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerVolumePduWrapper_StatusRotaryController">
                    <ho:SHORT-NAME>StatusRotaryController</ho:SHORT-NAME>
                    <fx:DATATYPE-REF ID-REF="bmw_software_idcevo_pdugateway_IDCevoTypes_StatusRotaryController"/>
                    <fx:UTILIZATION>
                        <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_2bit_invalidValue3_coding"/>
                        <fx:IS-HIGH-LOW-BYTE-ORDER>false</fx:IS-HIGH-LOW-BYTE-ORDER>
                    </fx:UTILIZATION>
                    <fx:POSITION>3</fx:POSITION>
                </fx:MEMBER>
                <fx:MEMBER ID="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerVolumePduWrapper_PaddingSignal2">
                    <ho:SHORT-NAME>PaddingSignal2</ho:SHORT-NAME>
                    <fx:DATATYPE-REF ID-REF="CURRENT_PROJECT_UInt64"/>
                    <fx:UTILIZATION>
                        <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_invalidValue16383_coding"/>
                        <fx:BIT-LENGTH>46</fx:BIT-LENGTH>
                        <fx:IS-HIGH-LOW-BYTE-ORDER>false</fx:IS-HIGH-LOW-BYTE-ORDER>
                    </fx:UTILIZATION>
                    <fx:POSITION>4</fx:POSITION>
                </fx:MEMBER>
                </fx:MEMBERS>
            </fx:DATATYPE>
   
            <fx:DATATYPE xsi:type="fx:ENUM-DATATYPE-TYPE" ID="bmw_software_idcevo_pdugateway_IDCevoTypes_StatusRotaryController">
                <ho:SHORT-NAME>StatusRotaryController</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_bmw_1_software_1_idcevo_1_pdugateway_1_IDCevoTypes_1"/>
                <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_2bit_invalidValue3_coding"/>
                <fx:ENUMERATION-ELEMENTS>
                <fx:ENUM-ELEMENT>
                    <fx:VALUE>0</fx:VALUE>
                    <fx:SYNONYM>button_not_pressed</fx:SYNONYM>
                </fx:ENUM-ELEMENT>
                <fx:ENUM-ELEMENT>
                    <fx:VALUE>1</fx:VALUE>
                    <fx:SYNONYM>button_pressed</fx:SYNONYM>
                </fx:ENUM-ELEMENT>
                <fx:ENUM-ELEMENT>
                    <fx:VALUE>3</fx:VALUE>
                    <fx:SYNONYM>Signal_unbefuellt</fx:SYNONYM>
                </fx:ENUM-ELEMENT>
                </fx:ENUMERATION-ELEMENTS>
            </fx:DATATYPE>

            <fx:DATATYPE xsi:type="fx:ENUM-DATATYPE-TYPE" ID="bmw_software_idcevo_pdugateway_IDCevoTypes_RotaryControllerDirection">
                <ho:SHORT-NAME>RotaryControllerDirection</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_bmw_1_software_1_idcevo_1_pdugateway_1_IDCevoTypes_1"/>
                <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_2bit_invalidValue3_coding"/>
                <fx:ENUMERATION-ELEMENTS>
                <fx:ENUM-ELEMENT>
                    <fx:VALUE>0</fx:VALUE>
                    <fx:SYNONYM>button_not_pressed</fx:SYNONYM>
                </fx:ENUM-ELEMENT>
                <fx:ENUM-ELEMENT>
                    <fx:VALUE>1</fx:VALUE>
                    <fx:SYNONYM>Volume_up</fx:SYNONYM>
                </fx:ENUM-ELEMENT>
                <fx:ENUM-ELEMENT>
                    <fx:VALUE>2</fx:VALUE>
                    <fx:SYNONYM>Volume_down</fx:SYNONYM>
                </fx:ENUM-ELEMENT>
                <fx:ENUM-ELEMENT>
                    <fx:VALUE>3</fx:VALUE>
                    <fx:SYNONYM>Signal_unbefuellt</fx:SYNONYM>
                </fx:ENUM-ELEMENT>
                </fx:ENUMERATION-ELEMENTS>
            </fx:DATATYPE>

            <fx:DATATYPE xsi:type="fx:COMMON-DATATYPE-TYPE" ID="CURRENT_PROJECT_UInt8">
                <ho:SHORT-NAME>UInt8</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_BMW_1"/>
                <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt8_coding"/>
            </fx:DATATYPE>

            <fx:DATATYPE xsi:type="fx:COMMON-DATATYPE-TYPE" ID="CURRENT_PROJECT_UInt64">
                <ho:SHORT-NAME>UInt64</ho:SHORT-NAME>
                <fx:PACKAGE-REF ID-REF="ID_P_BMW_1"/>
                <fx:CODING-REF ID-REF="CURRENT_PROJECT_UInt64_coding"/>
            </fx:DATATYPE>

            <fx:PROCESSING-INFORMATION>
                <fx:CODING ID="CURRENT_PROJECT_UInt8_coding">
                    <ho:SHORT-NAME>CODING_UInt8</ho:SHORT-NAME>
                    <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UINT8" CATEGORY="STANDARD-LENGTH-TYPE"/>
                </fx:CODING>

                <fx:CODING ID="CURRENT_PROJECT_UInt64_coding">
                    <ho:SHORT-NAME>CODING_UInt64</ho:SHORT-NAME>
                    <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UINT64" CATEGORY="STANDARD-LENGTH-TYPE"/>
                </fx:CODING>

                <fx:CODING ID="CURRENT_PROJECT_UInt8_2bit_invalidValue3_coding">
                    <ho:SHORT-NAME>CODING_UInt8_2bit_invalidValue3</ho:SHORT-NAME>
                    <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UINT8" CATEGORY="STANDARD-LENGTH-TYPE">
                        <ho:BIT-LENGTH>2</ho:BIT-LENGTH>
                    </ho:CODED-TYPE>
                </fx:CODING>

                <fx:CODING ID="CURRENT_PROJECT_UInt8_invalidValue63_coding">
                    <ho:SHORT-NAME>CODING_UInt8_invalidValue63</ho:SHORT-NAME>
                    <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UINT8" CATEGORY="STANDARD-LENGTH-TYPE"/>
                </fx:CODING>

                <fx:CODING ID="CURRENT_PROJECT_UInt8_invalidValue255_coding">
                    <ho:SHORT-NAME>CODING_UInt8_invalidValue255</ho:SHORT-NAME>
                    <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UINT8" CATEGORY="STANDARD-LENGTH-TYPE"/>
                </fx:CODING>

                <fx:CODING ID="CURRENT_PROJECT_UInt8_invalidValue16383_coding">
                    <ho:SHORT-NAME>CODING_UInt8_invalidValue16383</ho:SHORT-NAME>
                    <ho:CODED-TYPE ho:BASE-DATA-TYPE="A_UINT8" CATEGORY="STANDARD-LENGTH-TYPE"/>
                </fx:CODING>
            </fx:PROCESSING-INFORMATION>
        "#;

        let reader = FibexReader::from_reader(BufReader::new(StringReader::new(xml))).unwrap();
        let model = FibexParser::parse(vec![reader]).expect("parse failed");

        println!("types: {}", model.types.len());
        assert_eq!(6, model.types.len());
        assert_eq!(6, model.codings.len());

        let service = model.get_service(63841, 1).unwrap();
        println!("service: {}", service.name);
        let method = service.get_method(34077).unwrap();
        println!("method: {}", method.name);
        let fibex_type = method.get_request().unwrap();

        println!("request: {}", fibex_type.id);
        println!("{:#?}", fibex_type);

        let payload = [
            0x01, // RotaryControllerIncrement (UINT8-8Bit)
            0xfe, // RotaryControllerDirection (Enum<UINT8-2Bit>)
            0xfc, // PaddingSignal1 (UINT8-6Bit)
            0xff, // StatusRotaryController (Enum<UINT8-2Bit>)
            0xff, 0xff, 0xff, 0xff, // CURRENT_PROJECT_UInt64 (UIN64-46-Bit)
        ];

        let mut som_parser = SOMParser::new(&payload);
        let mut som_type = FibexTypes::build(fibex_type).expect("build");

        println!("SOM-TYPE\n{:#?}\n", som_type);

        println!("before:\n{}", som_type);
        let result = som_type.parse(&mut som_parser);
        println!("after:\n{}", som_type);
        println!("=> {:?}", result);

        println!("SOM-TYPE\n{:#?}\n", som_type);

        if let Ok(8) = result {
            println!("=> OK!");
        } else {
            panic!();
        }
    }
}
