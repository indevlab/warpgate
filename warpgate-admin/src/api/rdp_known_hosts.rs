use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::RdpKnownHost;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

/// List response that omits the full certificate DER bytes.
#[derive(Object, serde::Serialize)]
struct RdpKnownHostListItem {
    id: Uuid,
    target_id: Uuid,
    host: String,
    port: i32,
    certificate_sha256: String,
    created: OffsetDateTime,
    updated: OffsetDateTime,
}

impl From<RdpKnownHost::Model> for RdpKnownHostListItem {
    fn from(m: RdpKnownHost::Model) -> Self {
        Self {
            id: m.id,
            target_id: m.target_id,
            host: m.host,
            port: m.port,
            certificate_sha256: m.certificate_sha256,
            created: m.created,
            updated: m.updated,
        }
    }
}

#[derive(Object)]
struct AddRdpKnownHostRequest {
    host: String,
    port: i32,
    certificate_sha256: String,
    certificate_der_base64: Option<String>,
}

#[derive(ApiResponse)]
enum GetRdpKnownHostsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RdpKnownHostListItem>>),
}

#[derive(ApiResponse)]
enum GetRdpKnownHostResponse {
    #[oai(status = 200)]
    Ok(Json<RdpKnownHost::Model>),

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddRdpKnownHostResponse {
    #[oai(status = 201)]
    Created(Json<RdpKnownHost::Model>),

    #[oai(status = 409)]
    Conflict,
}

#[derive(ApiResponse)]
enum DeleteRdpKnownHostResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/targets/:id/rdp-known-hosts",
        method = "get",
        operation_id = "get_rdp_known_hosts"
    )]
    async fn get_rdp_known_hosts(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRdpKnownHostsResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let hosts = RdpKnownHost::Entity::find()
            .filter(RdpKnownHost::Column::TargetId.eq(id.0))
            .all(&*db)
            .await?;

        let items: Vec<RdpKnownHostListItem> = hosts.into_iter().map(Into::into).collect();
        Ok(GetRdpKnownHostsResponse::Ok(Json(items)))
    }

    #[oai(
        path = "/targets/:id/rdp-known-hosts/:sha256",
        method = "get",
        operation_id = "get_rdp_known_host"
    )]
    async fn get_rdp_known_host(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        sha256: Path<String>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetRdpKnownHostResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services.db.lock().await;

        let host = RdpKnownHost::Entity::find()
            .filter(RdpKnownHost::Column::TargetId.eq(id.0))
            .filter(RdpKnownHost::Column::CertificateSha256.eq(&*sha256))
            .one(&*db)
            .await?;

        match host {
            Some(host) => Ok(GetRdpKnownHostResponse::Ok(Json(host))),
            None => Ok(GetRdpKnownHostResponse::NotFound),
        }
    }

    #[oai(
        path = "/targets/:id/rdp-known-hosts",
        method = "post",
        operation_id = "add_rdp_known_host"
    )]
    async fn add_rdp_known_host(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        body: Json<AddRdpKnownHostRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddRdpKnownHostResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TargetsEdit)).await?;

        let db = ctx.services.db.lock().await;

        let existing = RdpKnownHost::Entity::find()
            .filter(RdpKnownHost::Column::TargetId.eq(id.0))
            .filter(RdpKnownHost::Column::CertificateSha256.eq(&body.certificate_sha256))
            .one(&*db)
            .await?;

        if existing.is_some() {
            return Ok(AddRdpKnownHostResponse::Conflict);
        }

        let now = OffsetDateTime::now_utc();
        let model = RdpKnownHost::ActiveModel {
            id: Set(Uuid::new_v4()),
            target_id: Set(id.0),
            host: Set(body.host.clone()),
            port: Set(body.port),
            certificate_sha256: Set(body.certificate_sha256.clone()),
            certificate_der_base64: Set(body.certificate_der_base64.clone().unwrap_or_default()),
            created: Set(now),
            updated: Set(now),
        }
        .insert(&*db)
        .await?;

        Ok(AddRdpKnownHostResponse::Created(Json(model)))
    }

    #[oai(
        path = "/targets/:id/rdp-known-hosts/:sha256",
        method = "delete",
        operation_id = "delete_rdp_known_host"
    )]
    async fn delete_rdp_known_host(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        sha256: Path<String>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteRdpKnownHostResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TargetsEdit)).await?;

        let db = ctx.services.db.lock().await;

        let host = RdpKnownHost::Entity::find()
            .filter(RdpKnownHost::Column::TargetId.eq(id.0))
            .filter(RdpKnownHost::Column::CertificateSha256.eq(&*sha256))
            .one(&*db)
            .await?;

        match host {
            Some(host) => {
                host.delete(&*db).await?;
                Ok(DeleteRdpKnownHostResponse::Deleted)
            }
            None => Ok(DeleteRdpKnownHostResponse::NotFound),
        }
    }
}
