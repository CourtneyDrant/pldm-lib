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

use crate::control_context::Tid;
use pldm_common::message::firmware_update::get_status::GetStatusReasonCode;
use pldm_common::protocol::firmware_update::{
    FirmwareDeviceState, PldmFdTime, UpdateOptionFlags, PLDM_FWUP_MAX_PADDING_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;

pub struct FdInternal {
    // Current state of the firmware device.
    state: FirmwareDeviceState,

    // Previous state of the firmware device.
    prev_state: FirmwareDeviceState,

    // Reason for the last transition to the idle state.
    // Only valid when `state == FirmwareDeviceState::Idle`.
    reason: Option<GetStatusReasonCode>,

    // Details of the component currently being updated.
    // Set by `UpdateComponent`, available during download/verify/apply.
    update_comp: FirmwareComponent,

    // Flags indicating update options.
    update_flags: UpdateOptionFlags,

    // Maximum transfer size allowed by the UA or platform implementation.
    max_xfer_size: u32,

    // Request details used for download/verify/apply operations.
    req: FdReq,

    // Mode-specific data for the requester.
    initiator_mode_state: InitiatorModeState,

    // Address of the Update Agent (UA).
    _ua_address: Option<Tid>,

    // Timestamp for FD T1 timeout in milliseconds.
    fd_t1_update_ts: PldmFdTime,

    fd_t1_timeout: PldmFdTime,
    fd_t2_retry_time: PldmFdTime,
}

impl Default for FdInternal {
    fn default() -> Self {
        Self::new(
            crate::config::FD_MAX_XFER_SIZE as u32,
            crate::config::DEFAULT_FD_T1_TIMEOUT,
            crate::config::DEFAULT_FD_T2_RETRY_TIME,
        )
    }
}

impl FdInternal {
    pub fn new(max_xfer_size: u32, fd_t1_timeout: u64, fd_t2_retry_time: u64) -> Self {
        Self {
            state: FirmwareDeviceState::Idle,
            prev_state: FirmwareDeviceState::Idle,
            reason: None,
            update_comp: FirmwareComponent::default(),
            update_flags: UpdateOptionFlags(0),
            max_xfer_size,
            req: FdReq::new(),
            initiator_mode_state: InitiatorModeState::Download(DownloadState::default()),
            _ua_address: None,
            fd_t1_update_ts: 0,
            fd_t1_timeout,
            fd_t2_retry_time,
        }
    }

    pub fn is_update_mode(&self) -> bool {
        self.state != FirmwareDeviceState::Idle
    }

    pub fn set_fd_state(&mut self, state: FirmwareDeviceState) {
        if self.state != state {
            self.prev_state = self.state.clone();
            self.state = state;
        }
    }

    pub fn set_fd_idle(&mut self, reason_code: GetStatusReasonCode) {
        if self.state != FirmwareDeviceState::Idle {
            self.prev_state = self.state.clone();
            self.state = FirmwareDeviceState::Idle;
            self.reason = Some(reason_code);
        }
    }

    pub fn fd_idle_timeout(&mut self) {
        let state = self.get_fd_state();
        let reason = match state {
            FirmwareDeviceState::Idle => return,
            FirmwareDeviceState::LearnComponents => GetStatusReasonCode::LearnComponentTimeout,
            FirmwareDeviceState::ReadyXfer => GetStatusReasonCode::ReadyXferTimeout,
            FirmwareDeviceState::Download => GetStatusReasonCode::DownloadTimeout,
            FirmwareDeviceState::Verify => GetStatusReasonCode::VerifyTimeout,
            FirmwareDeviceState::Apply => GetStatusReasonCode::ApplyTimeout,
            FirmwareDeviceState::Activate => GetStatusReasonCode::ActivateFw,
        };

        self.set_fd_idle(reason);
    }

    pub fn get_fd_reason(&self) -> Option<GetStatusReasonCode> {
        self.reason
    }

    pub fn get_fd_state(&self) -> FirmwareDeviceState {
        self.state.clone()
    }

    pub fn get_fd_prev_state(&self) -> FirmwareDeviceState {
        self.prev_state.clone()
    }

    pub fn set_xfer_size(&mut self, transfer_size: usize) {
        self.max_xfer_size = transfer_size as u32;
    }

    pub fn get_xfer_size(&self) -> usize {
        self.max_xfer_size as usize
    }

    pub fn set_component(&mut self, comp: &FirmwareComponent) {
        self.update_comp = comp.clone();
    }

    pub fn get_component(&self) -> FirmwareComponent {
        self.update_comp.clone()
    }

    pub fn set_update_flags(&mut self, flags: UpdateOptionFlags) {
        self.update_flags = flags;
    }

    pub fn get_update_flags(&self) -> UpdateOptionFlags {
        self.update_flags
    }

    pub fn set_fd_req(
        &mut self,
        req_state: FdReqState,
        complete: bool,
        result: Option<u8>,
        instance_id: Option<u8>,
        command: Option<u8>,
        sent_time: Option<PldmFdTime>,
    ) {
        self.req = FdReq {
            state: req_state,
            complete,
            result,
            instance_id,
            command,
            sent_time,
        };
    }

    pub fn alloc_next_instance_id(&mut self) -> Option<u8> {
        self.req.instance_id = Some(
            self.req
                .instance_id
                .map_or(1, |id| (id + 1) % crate::config::INSTANCE_ID_COUNT),
        );
        self.req.instance_id
    }

    pub fn get_fd_req(&self) -> FdReq {
        self.req.clone()
    }

    pub fn get_fd_req_state(&self) -> FdReqState {
        self.req.state.clone()
    }

    pub fn set_fd_req_state(&mut self, state: FdReqState) {
        self.req.state = state;
    }

    pub fn get_fd_sent_time(&self) -> Option<PldmFdTime> {
        self.req.sent_time
    }

    pub fn is_fd_req_complete(&self) -> bool {
        self.req.complete
    }

    pub fn get_fd_req_result(&self) -> Option<u8> {
        self.req.result
    }

    pub fn get_fd_download_chunk(
        &self,
        requested_offset: u32,
        requested_length: u32,
    ) -> Option<(u32, u32)> {
        if self.state != FirmwareDeviceState::Download {
            return None;
        }

        let comp_image_size = self.update_comp.comp_image_size.unwrap_or(0);
        if requested_offset > comp_image_size
            || requested_offset + requested_length
                > comp_image_size + PLDM_FWUP_MAX_PADDING_SIZE as u32
        {
            return None;
        }
        let chunk_size = requested_length.min(self.max_xfer_size);
        Some((requested_offset, chunk_size))
    }

    pub fn get_fd_download_state(&self) -> Option<(u32, u32)> {
        if let InitiatorModeState::Download(download) = &self.initiator_mode_state {
            Some((download.offset, download.length))
        } else {
            None
        }
    }

    pub fn set_fd_download_state(&mut self, offset: u32, length: u32) {
        if let InitiatorModeState::Download(download) = &mut self.initiator_mode_state {
            download.offset = offset;
            download.length = length;
        }
    }

    pub fn set_initiator_mode(&mut self, mode: InitiatorModeState) {
        self.initiator_mode_state = mode;
    }

    pub fn set_fd_verify_progress(&mut self, progress: u8) {
        if let InitiatorModeState::Verify(verify) = &mut self.initiator_mode_state {
            verify.progress_percent = progress;
        }
    }

    pub fn set_fd_apply_progress(&mut self, progress: u8) {
        if let InitiatorModeState::Apply(apply) = &mut self.initiator_mode_state {
            apply.progress_percent = progress;
        }
    }

    pub fn get_fd_verify_progress(&mut self) -> Option<u8> {
        if let InitiatorModeState::Verify(verify) = &mut self.initiator_mode_state {
            Some(verify.progress_percent)
        } else {
            None
        }
    }

    pub fn get_fd_apply_progress(&self) -> Option<u8> {
        if let InitiatorModeState::Apply(apply) = &self.initiator_mode_state {
            Some(apply.progress_percent)
        } else {
            None
        }
    }

    pub fn set_fd_t1_update_ts(&mut self, timestamp: PldmFdTime) {
        self.fd_t1_update_ts = timestamp;
    }

    pub fn get_fd_t1_update_ts(&self) -> PldmFdTime {
        self.fd_t1_update_ts
    }

    pub fn set_fd_t1_timeout(&mut self, timeout: PldmFdTime) {
        self.fd_t1_timeout = timeout;
    }

    pub fn get_fd_t1_timeout(&self) -> PldmFdTime {
        self.fd_t1_timeout
    }

    pub fn set_fd_t2_retry_time(&mut self, retry_time: PldmFdTime) {
        self.fd_t2_retry_time = retry_time;
    }

    pub fn get_fd_t2_retry_time(&self) -> PldmFdTime {
        self.fd_t2_retry_time
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdReqState {
    // The `pldm_fd_req` instance is unused.
    Unused,
    // Ready to send a request.
    Ready,
    // Waiting for a response.
    Sent,
    // Completed and failed; will not send more requests.
    Failed,
}

#[derive(Debug, Clone)]
pub struct FdReq {
    // The current state of the request.
    pub state: FdReqState,

    // Indicates if the request is complete and ready to transition to the next state.
    // This is relevant for TransferComplete, VerifyComplete, and ApplyComplete requests.
    pub complete: bool,

    // The result of the request, only valid when `complete` is set.
    pub result: Option<u8>,

    // The instance ID of the request, only valid in the `SENT` state.
    pub instance_id: Option<u8>,

    // The command associated with the request, only valid in the `SENT` state.
    pub command: Option<u8>,

    // The time when the request was sent, only valid in the `SENT` state.
    pub sent_time: Option<PldmFdTime>,
}

impl Default for FdReq {
    fn default() -> Self {
        Self::new()
    }
}

impl FdReq {
    fn new() -> Self {
        Self {
            state: FdReqState::Unused,
            complete: false,
            result: None,
            instance_id: None,
            command: None,
            sent_time: None,
        }
    }
}

#[derive(Debug)]
pub enum InitiatorModeState {
    Download(DownloadState),
    Verify(VerifyState),
    Apply(ApplyState),
}

#[derive(Debug, Default)]
pub struct DownloadState {
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Default)]
pub struct VerifyState {
    pub progress_percent: u8,
}

#[derive(Debug, Default)]
pub struct ApplyState {
    pub progress_percent: u8,
}
