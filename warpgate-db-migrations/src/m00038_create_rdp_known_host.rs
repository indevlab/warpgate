use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod rdp_known_host {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "rdp_known_hosts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub target_id: Uuid,
        pub host: String,
        pub port: i32,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub certificate_sha256: String,
        #[sea_orm(column_type = "Text")]
        pub certificate_der_base64: String,
        pub created: OffsetDateTime,
        pub updated: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::super::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "super::super::m00007_targets_and_roles::target::Column::Id",
            on_delete = "Cascade"
        )]
        Target,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00038_create_rdp_known_host"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(rdp_known_host::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(rdp_known_host::Entity)
                    .name("rdp_known_host__unique__target_host_port_sha256")
                    .unique()
                    .col(rdp_known_host::Column::TargetId)
                    .col(rdp_known_host::Column::Host)
                    .col(rdp_known_host::Column::Port)
                    .col(rdp_known_host::Column::CertificateSha256)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(rdp_known_host::Entity).to_owned())
            .await
    }
}
