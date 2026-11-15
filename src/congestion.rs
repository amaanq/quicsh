//! A congestion controller that starts as Cubic and becomes BBR once the
//! path loses packets for reasons other than a full queue.

use std::{
   any::Any,
   mem,
   sync::Arc,
   time::{
      Duration,
      Instant,
   },
};

use quinn_proto::{
   RttEstimator,
   congestion::{
      BbrConfig,
      Controller,
      ControllerFactory,
      ControllerMetrics,
      CubicConfig,
   },
};

/// How many losses at the start are left out. Cubic's first window is
/// several times what the path carries, and it takes that many to get under.
const START: u32 = 3;
/// How many losses are compared.
const SAMPLES: usize = 6;
/// How many times smaller than another a window at a loss has to be before
/// the path counts as one that drops packets on its own.
const SPREAD: u64 = 3;
/// How many initial windows a window has to hold to be compared. Under
/// heavy loss Cubic stays at a few dozen packets and loses them at about
/// the same window every time, as it would at a full queue.
const SMALL: u64 = 4;
/// How many losses at a smaller window say the same as a spread.
const STUCK: u32 = 3;
/// How long after the one before such a loss still counts with it. A shell
/// loses a packet now and then on any path.
const FRESH: Duration = Duration::from_secs(10);

/// Builds [`Adaptive`] controllers.
pub struct AdaptiveConfig;

impl ControllerFactory for AdaptiveConfig {
   fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
      Box::new(Adaptive {
         active:   Arc::new(CubicConfig::default()).build(now, current_mtu),
         switched: false,
         mtu:      current_mtu,
         starved:  true,
         flight:   0,
         epoch:    now,
         skipped:  0,
         windows:  [0; SAMPLES],
         count:    0,
         stuck:    0,
         recent:   now,
      })
   }
}

/// Cubic until it loses packets at full windows of very different sizes,
/// and BBR from then on. A full queue drops at the window that fills it,
/// and a path that drops packets on its own does so at any window.
pub struct Adaptive {
   /// The controller in charge.
   active:   Box<dyn Controller>,
   /// Whether that is BBR.
   switched: bool,
   /// The path's packet size.
   mtu:      u16,
   /// Whether the program had less to send than the window allows, when
   /// a loss says nothing about the window.
   starved:  bool,
   /// The most that was on its way since the last counted loss.
   flight:   u64,
   /// When the last counted loss was noticed. Packets sent before then
   /// belong to the same loss.
   epoch:    Instant,
   /// How many losses at the start were left out.
   skipped:  u32,
   /// The windows at the last losses that came while the window was in use
   /// and was large enough to compare.
   windows:  [u64; SAMPLES],
   /// How many of those there were.
   count:    usize,
   /// How many losses came at a window too small to compare, each soon
   /// after the one before.
   stuck:    u32,
   /// When the last of them came.
   recent:   Instant,
}

impl Controller for Adaptive {
   fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
      self.active.on_sent(now, bytes, last_packet_number);
   }

   fn on_ack(
      &mut self,
      now: Instant,
      sent: Instant,
      bytes: u64,
      app_limited: bool,
      rtt: &RttEstimator,
   ) {
      self.active.on_ack(now, sent, bytes, app_limited, rtt);
   }

   fn on_end_acks(
      &mut self,
      now: Instant,
      in_flight: u64,
      app_limited: bool,
      largest_packet_num_acked: Option<u64>,
   ) {
      self.starved = app_limited;
      self.flight = self.flight.max(in_flight);
      self
         .active
         .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
   }

   fn on_congestion_event(
      &mut self,
      now: Instant,
      sent: Instant,
      is_persistent_congestion: bool,
      lost_bytes: u64,
   ) {
      let window = self.active.window();

      self
         .active
         .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);

      if self.switched || self.starved || lost_bytes == 0 || sent <= self.epoch {
         return;
      }

      self.epoch = now;

      if self.skipped < START {
         self.skipped += 1;
         return;
      }

      // A loss under a window that was not in use says nothing about it.
      if mem::take(&mut self.flight).saturating_mul(4) < window.saturating_mul(3) {
         return;
      }

      if window < self.active.initial_window().saturating_mul(SMALL) {
         if now.duration_since(self.recent) > FRESH {
            self.stuck = 0;
         }

         self.stuck += 1;
         self.recent = now;
      } else {
         self.windows[self.count % SAMPLES] = window;
         self.count += 1;
      }

      let held = &self.windows[..self.count.min(SAMPLES)];
      let least = held.iter().min().copied().unwrap_or(0);
      let most = held.iter().max().copied().unwrap_or(0);

      if least.saturating_mul(SPREAD) < most || self.stuck >= STUCK {
         self.active = Arc::new(BbrConfig::default()).build(now, self.mtu);
         self.switched = true;
      }
   }

   fn on_mtu_update(&mut self, new_mtu: u16) {
      self.mtu = new_mtu;
      self.active.on_mtu_update(new_mtu);
   }

   fn window(&self) -> u64 {
      self.active.window()
   }

   fn metrics(&self) -> ControllerMetrics {
      self.active.metrics()
   }

   fn clone_box(&self) -> Box<dyn Controller> {
      Box::new(Self {
         active: self.active.clone_box(),
         ..*self
      })
   }

   fn initial_window(&self) -> u64 {
      self.active.initial_window()
   }

   fn into_any(self: Box<Self>) -> Box<dyn Any> {
      self
   }
}
