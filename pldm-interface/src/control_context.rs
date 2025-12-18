// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::cmd_interface::generate_failure_response;
use crate::error::MsgHandlerError;
use core::sync::atomic::{AtomicUsize, Ordering};
use pldm_common::codec::PldmCodec;
use pldm_common::error::PldmError;
use pldm_common::message::control::{
    GetPldmCommandsRequest, GetPldmCommandsResponse, GetPldmTypeRequest, GetPldmTypeResponse,
    GetPldmVersionRequest, GetPldmVersionResponse, GetTidRequest, GetTidResponse, SetTidRequest,
    SetTidResponse,
};
use pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmControlCompletionCode, PldmSupportedType, TransferOperationFlag,
    TransferRespFlag,
};
use pldm_common::protocol::version::{PldmVersion, ProtocolVersionStr, Ver32};

pub type Tid = u8;
pub type CmdOpCode = u8;
pub const UNASSIGNED_TID: Tid = 0;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ProtocolCapability<'a> {
    pub pldm_type: PldmSupportedType,
    pub protocol_version: Ver32,
    pub supported_commands: &'a [CmdOpCode],
}

impl<'a> ProtocolCapability<'a> {
    pub fn new(
        pldm_type: PldmSupportedType,
        protocol_version: ProtocolVersionStr,
        supported_commands: &'a [CmdOpCode],
    ) -> Result<Self, PldmError> {
        Ok(Self {
            pldm_type,
            protocol_version: match PldmVersion::try_from(protocol_version) {
                Ok(ver) => ver.bcd_encode_to_ver32(),
                Err(_) => return Err(PldmError::InvalidProtocolVersion),
            },
            supported_commands,
        })
    }
}

/// `ControlContext` is a structure that holds the control context for the PLDM library.
///
/// # Fields
///
/// * `tid` - An atomic unsigned size integer representing the transaction ID.
/// * `capabilities` - A reference to a slice of `ProtocolCapability` which represents the protocol capabilities.
pub struct ControlContext<'a> {
    tid: AtomicUsize,
    capabilities: &'a [ProtocolCapability<'a>],
}

impl<'a> ControlContext<'a> {
    pub fn new(capabilities: &'a [ProtocolCapability<'a>]) -> Self {
        Self {
            tid: AtomicUsize::new(UNASSIGNED_TID as usize),
            capabilities,
        }
    }

    pub fn get_tid(&self) -> Tid {
        self.tid.load(Ordering::SeqCst) as Tid
    }

    pub fn set_tid(&self, tid: Tid) {
        self.tid.store(tid as usize, Ordering::SeqCst);
    }

    pub fn get_supported_commands(
        &self,
        pldm_type: PldmSupportedType,
        protocol_version: Ver32,
    ) -> Option<&[CmdOpCode]> {
        self.capabilities
            .iter()
            .find(|cap| cap.pldm_type == pldm_type && cap.protocol_version == protocol_version)
            .map(|cap| cap.supported_commands)
    }

    pub fn get_protocol_versions(
        &self,
        pldm_type: PldmSupportedType,
        versions: &mut [Ver32],
    ) -> usize {
        let mut count = 0;
        for cap in self
            .capabilities
            .iter()
            .filter(|cap| cap.pldm_type == pldm_type)
        {
            if count < versions.len() {
                versions[count] = cap.protocol_version;
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    pub fn get_supported_types(&self, types: &mut [u8]) -> usize {
        let mut count = 0;
        for cap in self.capabilities.iter() {
            let pldm_type = cap.pldm_type as u8;
            if !types[..count].contains(&pldm_type) {
                if count < types.len() {
                    types[count] = pldm_type;
                    count += 1;
                } else {
                    break;
                }
            }
        }
        count
    }

    pub fn is_supported_type(&self, pldm_type: PldmSupportedType) -> bool {
        self.capabilities
            .iter()
            .any(|cap| cap.pldm_type == pldm_type)
    }

    pub fn is_supported_version(
        &self,
        pldm_type: PldmSupportedType,
        protocol_version: Ver32,
    ) -> bool {
        self.capabilities
            .iter()
            .any(|cap| cap.pldm_type == pldm_type && cap.protocol_version == protocol_version)
    }

    pub fn is_supported_command(&self, pldm_type: PldmSupportedType, cmd: u8) -> bool {
        self.capabilities
            .iter()
            .find(|cap| cap.pldm_type == pldm_type)
            .is_some_and(|cap| cap.supported_commands.contains(&cmd))
    }
}

/// Trait representing a responder for control commands in the PLDM protocol.
/// Implementors of this trait are responsible for handling various control commands
/// and generating appropriate responses.
///
/// # Methods
///
/// - `get_tid_rsp`: Generates a response for the "Get TID" command.
/// - `set_tid_rsp`: Generates a response for the "Set TID" command.
/// - `get_pldm_types_rsp`: Generates a response for the "Get PLDM Types" command.
/// - `get_pldm_commands_rsp`: Generates a response for the "Get PLDM Commands" command.
/// - `get_pldm_version_rsp`: Generates a response for the "Get PLDM Version" command.
///
/// Each method takes a mutable reference to a payload buffer and returns a `Result`
/// containing the size of the response or a `MsgHandlerError` if an error occurs.
pub trait CtrlCmdResponder {
    fn get_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn set_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn get_pldm_types_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn get_pldm_commands_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
    fn get_pldm_version_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError>;
}

impl CtrlCmdResponder for ControlContext<'_> {
    fn get_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = GetTidRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        let resp = GetTidResponse::new(
            req.hdr.instance_id(),
            self.get_tid(),
            PldmBaseCompletionCode::Success as u8,
        );
        resp.encode(payload).map_err(MsgHandlerError::Codec)
    }

    fn set_tid_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = SetTidRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        self.set_tid(req.tid);
        let resp =
            SetTidResponse::new(req.hdr.instance_id(), PldmBaseCompletionCode::Success as u8);
        resp.encode(payload).map_err(MsgHandlerError::Codec)
    }

    fn get_pldm_types_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = GetPldmTypeRequest::decode(payload).map_err(MsgHandlerError::Codec)?;
        let mut types = [0x0u8; 6];
        let num_types = self.get_supported_types(&mut types);
        let resp = GetPldmTypeResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            &types[..num_types],
        );
        resp.encode(payload).map_err(MsgHandlerError::Codec)
    }

    fn get_pldm_commands_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = match GetPldmCommandsRequest::decode(payload) {
            Ok(req) => req,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::InvalidLength as u8,
                )
            }
        };

        let pldm_type_in_req = match PldmSupportedType::try_from(req.pldm_type) {
            Ok(pldm_type) => pldm_type,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
                )
            }
        };

        if !self.is_supported_type(pldm_type_in_req) {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
            );
        }

        let version_in_req = req.protocol_version;
        if !self.is_supported_version(pldm_type_in_req, version_in_req) {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidPldmVersionInRequestData as u8,
            );
        }

        let cmds = self
            .get_supported_commands(pldm_type_in_req, version_in_req)
            .unwrap();

        let resp = GetPldmCommandsResponse::new(
            req.hdr.instance_id(),
            PldmBaseCompletionCode::Success as u8,
            cmds,
        );

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }

    fn get_pldm_version_rsp(&self, payload: &mut [u8]) -> Result<usize, MsgHandlerError> {
        let req = match GetPldmVersionRequest::decode(payload) {
            Ok(req) => req,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmBaseCompletionCode::InvalidLength as u8,
                )
            }
        };

        let pldm_type_in_req = match PldmSupportedType::try_from(req.pldm_type) {
            Ok(pldm_type) => pldm_type,
            Err(_) => {
                return generate_failure_response(
                    payload,
                    PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
                )
            }
        };

        if !self.is_supported_type(pldm_type_in_req) {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidPldmTypeInRequestData as u8,
            );
        }

        if req.transfer_op_flag != TransferOperationFlag::GetFirstPart as u8 {
            return generate_failure_response(
                payload,
                PldmControlCompletionCode::InvalidTransferOperationFlag as u8,
            );
        }

        let mut versions = [0u32; 2];
        if self.get_protocol_versions(pldm_type_in_req, &mut versions) == 0 {
            return generate_failure_response(payload, PldmBaseCompletionCode::Error as u8);
        }

        // Only one version is supported for now
        let resp = GetPldmVersionResponse {
            hdr: req.hdr.into_response(),
            completion_code: PldmBaseCompletionCode::Success as u8,
            next_transfer_handle: 0,
            transfer_rsp_flag: TransferRespFlag::StartAndEnd as u8,
            version_data: versions[0],
        };

        match resp.encode(payload) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                generate_failure_response(payload, PldmBaseCompletionCode::InvalidLength as u8)
            }
        }
    }
}
