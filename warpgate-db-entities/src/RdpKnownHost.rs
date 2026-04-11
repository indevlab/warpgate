use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::ForeignKeyAction;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "rdp_known_hosts")]
#[oai(rename = "RdpKnownHost")]
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

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Target,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Target => Entity::belongs_to(super::Target::Entity)
                .from(Column::TargetId)
                .to(super::Target::Column::Id)
                .on_delete(ForeignKeyAction::Cascade)
                .into(),
        }
    }
}

impl Related<super::Target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Target.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
