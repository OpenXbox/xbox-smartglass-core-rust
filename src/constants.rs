pub mod uuid {
    use uuid::Uuid;
    use ::util::UUID;
    lazy_static! {
        pub static ref SYSTEM_INPUT: UUID<u8> = UUID::<u8>::new(Uuid::parse_str("fa20b8ca-66fb-46e0-adb6-0b978a59d35f").unwrap());
        pub static ref SYSTEM_INPUT_TV_REMOTE: UUID<u8> = UUID::<u8>::new(Uuid::parse_str("d451e3b3-60bb-4c71-b3db-f994b1aca3a7").unwrap());
        pub static ref SYSTEM_MEDIA: UUID<u8> = UUID::<u8>::new(Uuid::parse_str("48a9ca24-eb6d-4e12-8c43-d57469edd3cd").unwrap());
        pub static ref SYSTEM_TEXT: UUID<u8> = UUID::<u8>::new(Uuid::parse_str("7af3e6a2-488b-40cb-a931-79c04b7da3a0").unwrap());
        pub static ref SYSTEM_BROADCAST: UUID<u8> = UUID::<u8>::new(Uuid::parse_str("b6a117d8-f5e2-45d7-862e-8fd8e3156476").unwrap());
    }
}