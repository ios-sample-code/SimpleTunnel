/*
	Copyright (C) 2015 Apple Inc. All Rights Reserved.
	See LICENSE.txt for this sample’s licensing information
	
	Abstract:
	This file contains the ClientTunnel class. The ClientTunnel class implements the client side of the SimpleTunnel tunneling protocol.
*/

import Foundation
import NetworkExtension

/// The client-side implementation of the SimpleTunnel protocol.
public class ClientTunnel: Tunnel {

	// MARK: Properties

	/// The tunnel connection.
	public var connection: NWTCPConnection?

	/// The last error that occurred on the tunnel.
	public var lastError: NSError?

	/// The previously-received incomplete message data.
	var previousData: NSMutableData?

	/// The address of the tunnel server.
	public var remoteHost: String?

	// MARK: Interface

	/// Start the TCP connection to the tunnel server.
	public func startTunnel(provider: NETunnelProvider) -> SimpleTunnelError? {

		guard let serverAddress = provider.protocolConfiguration.serverAddress else {
			return .BadConfiguration
		}

		let endpoint: NWEndpoint

		if let colonRange = serverAddress.rangeOfCharacterFromSet(NSCharacterSet(charactersInString: ":"), options: [], range: nil) {
			// The server is specified in the configuration as <host>:<port>.
			let hostname = serverAddress.substringWithRange(Range<String.Index>(start:serverAddress.startIndex, end:colonRange.startIndex))
			let portString = serverAddress.substringWithRange(Range<String.Index>(start:colonRange.startIndex.successor(), end:serverAddress.endIndex))

			guard !hostname.isEmpty && !portString.isEmpty else {
				return .BadConfiguration
			}

			endpoint = NWHostEndpoint(hostname:hostname, port:portString)
		}
		else {
			// The server is specified in the configuration as a Bonjour service name.
			endpoint = NWBonjourServiceEndpoint(name: serverAddress, type:Tunnel.serviceType, domain:Tunnel.serviceDomain)
		}

		// Kick off the connection to the server.
		connection = provider.createTCPConnectionToEndpoint(endpoint, enableTLS:false, TLSParameters:nil, delegate:nil)

		// Register for notificationes when the connection status changes.
		connection!.addObserver(self, forKeyPath: "state", options: .Initial, context: &connection)

		return nil
	}

	/// Close the tunnel.
	public func closeTunnelWithError(error: NSError?) {
		lastError = error
		closeTunnel()
	}

	/// Handle data read from the tunnel connection.
	func handleReadEvent(data: NSData?, error: NSError?) {
		if let readError = error {
			print("Got an error on the tunnel connection: \(readError)")
			closeTunnelWithError(readError)
			return
		}
		guard let newData = data else {
			// EOF
			closeTunnel()
			return
		}

		// If there is a previously-read incomplete message, append the new data to what was previously read.
		var currentData = newData
		if let oldData = previousData {
			oldData.appendData(newData)
			currentData = oldData
			previousData = nil
		}

		// Start out by looking at all of the data.
		var currentRange = Range(start: 0, end: currentData.length)

		while currentRange.count > sizeof(UInt32.self) {
			var totalLength: UInt32 = 0

			// Parse out the total length of the message, which is stored in the first 4 bytes of the message.
			let lengthRange = Range(start: currentRange.startIndex, end: currentRange.startIndex + sizeofValue(totalLength))
			currentData.getBytes(&totalLength, range: NSRange(lengthRange))

			// If we don't have the entire message, stop parsing.
			guard currentRange.count >= Int(totalLength) else { break }

			// Move past the first 4 bytes holding the total length.
			currentRange = rangeByMovingStartOfRange(currentRange, byCount: sizeofValue(totalLength))

			// Subtract the size of the total length from the total length of the message to get the message payload length.
			let payloadLength = Int(totalLength - UInt32(sizeofValue(totalLength)))

			// Get the payload and handle the message.
			let range = Range(start: currentRange.startIndex, end: currentRange.startIndex + payloadLength)
			handlePacket(currentData.subdataWithRange(NSRange(range)))

			// Move past the payload.
			currentRange = rangeByMovingStartOfRange(currentRange, byCount: payloadLength)
		}

		// If we have data left, then save the incomplete message for when we get more data from the tunnel connection.
		if !currentRange.isEmpty {
			previousData = NSMutableData(data: currentData.subdataWithRange(NSRange(currentRange)))
		}

		guard let targetConnection = connection else { return }

		// Kick off another read operation.
		targetConnection.readMinimumLength(sizeof(UInt32.self), maximumLength: Tunnel.packetSize) { data, error in
			self.handleReadEvent(data, error: error)
		}
	}

	/// Send a message to the tunnel server.
	public func sendMessage(messageProperties: [String: AnyObject], completionHandler: (NSError?) -> Void) {
		guard let messageData = serializeMessage(messageProperties) else {
			completionHandler(SimpleTunnelError.InternalError as NSError)
			return
		}

		connection?.write(messageData, completionHandler: completionHandler)
	}

	// MARK: NSObject

	/// Handle changes to the tunnel connection state.
	public override func observeValueForKeyPath(keyPath: String?, ofObject object: AnyObject?, change: [String: AnyObject]?, context: UnsafeMutablePointer<Void>) {
		guard keyPath == "state" && UnsafeMutablePointer<NWTCPConnection?>(context).memory == connection else {
			super.observeValueForKeyPath(keyPath, ofObject: object, change: change, context: context)
			return
		}

		switch connection!.state {
			case .Connected:
				// Let the delegate know that the tunnel is open, and start reading from the tunnel connection.
				delegate?.tunnelDidOpen(self)
				connection!.readMinimumLength(sizeof(UInt32.self), maximumLength: Tunnel.packetSize) { data, error in
					self.handleReadEvent(data, error: error)
				}

			case .Disconnected:
				closeTunnelWithError(connection!.error)

			case .Cancelled:
				connection!.removeObserver(self, forKeyPath:"state", context:&connection)
				connection = nil
				delegate?.tunnelDidClose(self)

			default:
				break
		}
	}

	// MARK: Tunnel

	/// Close the tunnel.
	override public func closeTunnel() {
		// Close the tunnel connection.
		if let TCPConnection = connection {
			TCPConnection.cancel()
		}
		super.closeTunnel()
	}

	/// Write data to the tunnel connection.
	override func writeDataToTunnel(data: NSData, startingAtOffset: Int) -> Int {
		connection?.write(data) { error in
			self.closeTunnelWithError(error)
		}
		return data.length
	}

	/// Handle a message received from the tunnel server.
	override func handleMessage(commandType: TunnelCommand, properties: [String: AnyObject], connection: Connection?) -> Bool {
		var success = true

		switch commandType {
			case .OpenResult:
				// A logical connection was opened successfully.
				guard let targetConnection = connection,
					resultCodeNumber = properties[TunnelMessageKey.ResultCode.rawValue] as? Int,
					resultCode = TunnelConnectionOpenResult(rawValue: resultCodeNumber)
					else
				{
					success = false
					break
				}

				if let remoteAddress = self.connection!.remoteAddress as? NWHostEndpoint {
					remoteHost = remoteAddress.hostname
				}
				targetConnection.handleOpenCompleted(resultCode, properties:properties)
			
			default:
				print("Tunnel received an invalid command")
				success = false
		}
		return success
	}
}
