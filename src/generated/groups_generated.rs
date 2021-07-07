/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;

/// Group approval policy.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct GroupApprovalPolicy {
    #[serde(flatten)]
    pub policy: QuorumPolicy,
    /// When this is true, manage operations on security objects require approval.
    pub protect_manage_operations: Option<bool>,
    /// When this is true, cryptographic operations on security objects require approval.
    pub protect_crypto_operations: Option<bool>,
}

#[derive(PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Clone)]
pub struct HmgConfig {
    pub kind: HmgKind,
    pub url: String,
    pub tls: TlsConfig,
    #[serde(default)]
    pub slot: Option<usize>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub hsm_order: Option<i32>,
    #[serde(default)]
    pub access_key: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub subscription_id: Option<Uuid>,
    #[serde(default)]
    pub key_vault_type: Option<String>,
}

#[derive(Eq, Debug, PartialEq, Hash, Copy, Serialize, Deserialize, Clone)]
pub enum HmgRedundancyScheme {
    PriorityFailover,
}

#[derive(Debug, Eq, PartialEq, Copy, Hash, Serialize, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum HmgKind {
    Ncipher,
    Safenet,
    AwsCloudHsm,
    Fortanix,
    FortanixFipsCluster,
    AwsKms,
    AzureKeyVault,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyVault {
    pub id: String,
    pub name: String,
    pub vault_type: String,
    pub location: String,
    #[serde(default)]
    pub tags: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    pub acct_id: Uuid,
    #[serde(default)]
    pub approval_policy: Option<GroupApprovalPolicy>,
    pub created_at: Time,
    pub creator: Principal,
    #[serde(default)]
    pub cryptographic_policy: Option<CryptographicPolicy>,
    #[serde(default)]
    pub custodian_policy: Option<QuorumPolicy>,
    #[serde(default)]
    pub description: Option<String>,
    pub group_id: Uuid,
    #[serde(default)]
    pub hmg: Option<HashMap<Uuid, HmgConfig>>,
    #[serde(default)]
    pub hmg_redundancy: Option<HmgRedundancyScheme>,
    #[serde(default)]
    pub hmg_segregation: Option<bool>,
    #[serde(default)]
    pub hmg_sync: Option<bool>,
    #[serde(default)]
    pub key_history_policy: Option<KeyHistoryPolicy>,
    pub name: String,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct GroupRequest {
    #[serde(default)]
    pub add_hmg: Option<Vec<HmgConfig>>,
    #[serde(default)]
    pub approval_policy: Option<GroupApprovalPolicy>,
    #[serde(default)]
    pub cryptographic_policy: Option<Option<CryptographicPolicy>>,
    #[serde(default)]
    pub custodian_policy: Option<QuorumPolicy>,
    #[serde(default)]
    pub del_hmg: Option<HashSet<Uuid>>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub hmg_redundancy: Option<HmgRedundancyScheme>,
    #[serde(default)]
    pub hmg_segregation: Option<bool>,
    #[serde(default)]
    pub hmg_sync: Option<bool>,
    #[serde(default)]
    pub key_history_policy: Option<Option<KeyHistoryPolicy>>,
    #[serde(default)]
    pub mod_hmg: Option<HashMap<Uuid, HmgConfig>>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct CheckHmgRequest {
    /// The ID of the hmg configuration in the group.
    pub id: Option<Uuid>,
    pub config: Option<HmgConfig>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct ScanHmgRequest {
    pub config: Option<HmgConfig>,
}

pub struct OperationListGroups;
#[allow(unused)]
impl Operation for OperationListGroups {
    type PathParams = ();
    type QueryParams = ();
    type Body = ();
    type Output = Vec<Group>;

    fn method() -> Method {
        Method::Get
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups")
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        None
    }
}

impl SdkmsClient {
    pub fn list_groups(&self) -> Result<Vec<Group>> {
        self.execute::<OperationListGroups>(&(), (), None)
    }
}

pub struct OperationGetGroup;
#[allow(unused)]
impl Operation for OperationGetGroup {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = Group;

    fn method() -> Method {
        Method::Get
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        None
    }
}

impl SdkmsClient {
    pub fn get_group(&self, id: &Uuid) -> Result<Group> {
        self.execute::<OperationGetGroup>(&(), (id,), None)
    }
}

pub struct OperationCreateGroup;
#[allow(unused)]
impl Operation for OperationCreateGroup {
    type PathParams = ();
    type QueryParams = ();
    type Body = GroupRequest;
    type Output = Group;

    fn method() -> Method {
        Method::Post
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups")
    }
}

impl SdkmsClient {
    pub fn create_group(&self, req: &GroupRequest) -> Result<Group> {
        self.execute::<OperationCreateGroup>(req, (), None)
    }
}

pub struct OperationUpdateGroup;
#[allow(unused)]
impl Operation for OperationUpdateGroup {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = GroupRequest;
    type Output = Group;

    fn method() -> Method {
        Method::Patch
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}", id = p.0)
    }
}

impl SdkmsClient {
    pub fn update_group(&self, id: &Uuid, req: &GroupRequest) -> Result<Group> {
        self.execute::<OperationUpdateGroup>(req, (id,), None)
    }
    pub fn request_approval_to_update_group(
        &self,
        id: &Uuid,
        req: &GroupRequest,
        description: Option<String>,
    ) -> Result<PendingApproval<OperationUpdateGroup>> {
        self.request_approval::<OperationUpdateGroup>(req, (id,), None, description)
    }
}

pub struct OperationDeleteGroup;
#[allow(unused)]
impl Operation for OperationDeleteGroup {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ();
    type Output = ();

    fn method() -> Method {
        Method::Delete
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}", id = p.0)
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> {
        None
    }
}

impl SdkmsClient {
    pub fn delete_group(&self, id: &Uuid) -> Result<()> {
        self.execute::<OperationDeleteGroup>(&(), (id,), None)
    }
}

pub struct OperationCheckHmgConfig;
#[allow(unused)]
impl Operation for OperationCheckHmgConfig {
    type PathParams = ();
    type QueryParams = ();
    type Body = HmgConfig;
    type Output = ();

    fn method() -> Method {
        Method::Post
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/hmg/check")
    }
}

impl SdkmsClient {
    pub fn check_hmg_config(&self, req: &HmgConfig) -> Result<()> {
        self.execute::<OperationCheckHmgConfig>(req, (), None)
    }
}

pub struct OperationGetVaults;
#[allow(unused)]
impl Operation for OperationGetVaults {
    type PathParams = ();
    type QueryParams = ();
    type Body = HmgConfig;
    type Output = Vec<KeyVault>;

    fn method() -> Method {
        Method::Post
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/hmg/azure_vaults")
    }
}

impl SdkmsClient {
    pub fn get_vaults(&self, req: &HmgConfig) -> Result<Vec<KeyVault>> {
        self.execute::<OperationGetVaults>(req, (), None)
    }
}

pub struct OperationCheckHmg;
#[allow(unused)]
impl Operation for OperationCheckHmg {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = CheckHmgRequest;
    type Output = ();

    fn method() -> Method {
        Method::Post
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}/hmg/check", id = p.0)
    }
}

impl SdkmsClient {
    pub fn check_hmg(&self, id: &Uuid, req: &CheckHmgRequest) -> Result<()> {
        self.execute::<OperationCheckHmg>(req, (id,), None)
    }
}

pub struct OperationScanHmg;
#[allow(unused)]
impl Operation for OperationScanHmg {
    type PathParams = (Uuid,);
    type QueryParams = ();
    type Body = ScanHmgRequest;
    type Output = Vec<Sobject>;

    fn method() -> Method {
        Method::Post
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/groups/{id}/hmg/scan", id = p.0)
    }
}

impl SdkmsClient {
    pub fn scan_hmg(&self, id: &Uuid, req: &ScanHmgRequest) -> Result<Vec<Sobject>> {
        self.execute::<OperationScanHmg>(req, (id,), None)
    }
}
