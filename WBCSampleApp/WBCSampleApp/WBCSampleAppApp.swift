//
//  WBCSampleAppApp.swift
//  WBCSampleApp
//
//  Created by Sanjay Dey on 2024-12-10.
//

import SwiftUI

@main
struct WBCSampleAppApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: ContentViewModel())
        }
    }
}
