/*
	Copyright (C) 2015 Apple Inc. All Rights Reserved.
	See LICENSE.txt for this sample’s licensing information
	
	Abstract:
	This file contains the AppProxyProvider class. The AppProxyProvider class is a sub-class of NEAppProxyProvider, and is the integration point between the Network Extension framework and the SimpleTunnel tunneling protocol.
*/

import NetworkExtension
import SimpleTunnelServices

/// A NEAppProxyProvider sub-class that implements the client side of the SimpleTunnel tunneling protocol.
class AppProxyProvider: NEAppProxyProvider, TunnelDelegate {

	// MARK: Properties

	/// A reference to the tunnel object.
	var tunnel: ClientTunnel?

	/// The completion handler to call when the tunnel is fully established.
	var pendingStartCompletion: (NSError? -> Void)?

	/// The completion handler to call when the tunnel is fully disconnected.
	var pendingStopCompletion: (Void -> Void)?

	// MARK: NEAppProxyProvider

	/// Begin the process of establishing the tunnel.
	override func startProxyWithOptions(options: [String : AnyObject]?, completionHandler: (NSError?) -> Void) {

		let newTunnel = ClientTunnel()
		newTunnel.delegate = self

		if let error = newTunnel.startTunnel(self) {
			completionHandler(error as NSError)
			return
		}

		pendingStartCompletion = completionHandler
		tunnel = newTunnel
	}

	/// Begin the process of stopping the tunnel.
	override func stopProxyWithReason(reason: NEProviderStopReason, completionHandler: () -> Void) {

		// Clear out any pending start completion handler.
		pendingStartCompletion = nil

		pendingStopCompletion = completionHandler
		tunnel?.closeTunnel()
	}

	/// Handle a new flow of network data created by an application.
	override func handleNewFlow(flow: (NEAppProxyFlow?)) -> Bool {
		var newConnection: ClientAppProxyConnection?

		guard let clientTunnel = tunnel else { return false }

		if let TCPFlow = flow as? NEAppProxyTCPFlow {
			newConnection = ClientAppProxyTCPConnection(tunnel: clientTunnel, newTCPFlow: TCPFlow)
		}
		else if let UDPFlow = flow as? NEAppProxyUDPFlow {
			newConnection = ClientAppProxyUDPConnection(tunnel: clientTunnel, newUDPFlow: UDPFlow)
		}

		guard newConnection != nil else { return false }

		newConnection!.open()

		return true
	}

	// MARK: TunnelDelegate

	/// Handle the event of the tunnel being fully established.
	func tunnelDidOpen(targetTunnel: Tunnel) {

		// Call the pending start completion handler
		pendingStartCompletion?(nil)
		pendingStartCompletion = nil
	}

	/// Handle the event of the tunnel being fully disconnected.
	func tunnelDidClose(targetTunnel: Tunnel) {

		// Call the appropriate completion handler depending on the current pending tunnel operation.
		if pendingStartCompletion != nil {
			pendingStartCompletion?(tunnel?.lastError)
			pendingStartCompletion = nil
		}
		else if pendingStopCompletion != nil {
			pendingStopCompletion?()
			pendingStopCompletion = nil
		}
		else {
			// No completion handler, so cancel the proxy.
			cancelProxyWithError(tunnel?.lastError)
		}
		tunnel = nil
	}
}
